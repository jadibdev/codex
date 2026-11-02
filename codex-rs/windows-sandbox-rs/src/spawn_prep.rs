use crate::acl::add_allow_ace;
use crate::acl::add_deny_write_ace;
use crate::acl::allow_null_device;
use crate::acl::ensure_allow_write_aces;
use crate::allow::AllowDenyPaths;
use crate::allow::compute_allow_paths_for_permissions;
use crate::cap::load_or_create_cap_sids;
use crate::cap::workspace_write_cap_sid_for_root;
use crate::cap::workspace_write_root_contains_path;
use crate::cap::workspace_write_root_overlaps_path;
use crate::cap::workspace_write_root_specificity;
use crate::deny_read_state::sync_persistent_deny_read_acls;
use crate::env::apply_no_network_to_env;
use crate::env::ensure_non_interactive_pager;
use crate::env::inherit_path_env;
use crate::env::normalize_null_device_env;
use crate::identity::SandboxCreds;
use crate::identity::require_logon_sandbox_creds;
use crate::logging::log_start;
use crate::no_reparse_dir::DirectoryOpenDisposition;
use crate::no_reparse_dir::open_directory_no_reparse;
use crate::no_reparse_dir::open_no_reparse;
use crate::no_reparse_dir::validate_local_directory_path;
use crate::path_normalization::canonical_path_key;
use crate::path_normalization::canonicalize_path;
use crate::resolved_permissions::ResolvedWindowsSandboxPermissions;
use crate::sandbox_utils::ensure_codex_home_exists;
use crate::sandbox_utils::inject_git_safe_directory;
use crate::setup::effective_write_roots_for_permissions;
use crate::token::LocalSid;
use crate::token::create_readonly_token_with_cap;
use crate::token::create_workspace_write_token_with_caps_from;
use crate::token::get_current_token_for_restriction;
use crate::token::get_logon_sid_bytes;
use crate::workspace_acl::is_command_cwd_root;
use crate::workspace_acl::protect_workspace_agents_dir;
use crate::workspace_acl::protect_workspace_codex_dir;
use anyhow::Context;
use anyhow::Result;
use codex_protocol::models::PermissionProfile;
use codex_utils_absolute_path::AbsolutePathBuf;
use std::collections::HashMap;
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;
use std::os::windows::io::OwnedHandle;
use std::path::Path;
use std::path::PathBuf;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Storage::FileSystem::DELETE;
use windows_sys::Win32::Storage::FileSystem::FILE_DISPOSITION_INFO;
use windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_DELETE;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE;
use windows_sys::Win32::Storage::FileSystem::FILE_STANDARD_INFO;
use windows_sys::Win32::Storage::FileSystem::FILE_TRAVERSE;
use windows_sys::Win32::Storage::FileSystem::FileDispositionInfo;
use windows_sys::Win32::Storage::FileSystem::FileStandardInfo;
use windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandleEx;
use windows_sys::Win32::Storage::FileSystem::ReOpenFile;
use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
use windows_sys::Win32::Storage::FileSystem::SetFileInformationByHandle;

const FILE_CREATE: u32 = 2;
const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;

/// Placeholders created for this spawn, deleted on drop unless committed.
///
/// Each handle holds only `FILE_READ_ATTRIBUTES | SYNCHRONIZE`, which do not
/// participate in sharing checks, so the sandboxed child can open the file with
/// any share mode while the guard is alive. Rollback reopens the same file
/// object with `DELETE` instead of looking the path up again.
pub(crate) struct PlaceholderRollbackGuard {
    entries: Vec<(PathBuf, OwnedHandle)>,
    logs_base_dir: Option<PathBuf>,
    committed: bool,
}

impl PlaceholderRollbackGuard {
    pub(crate) fn new(logs_base_dir: Option<&Path>) -> Self {
        Self {
            entries: Vec::new(),
            logs_base_dir: logs_base_dir.map(Path::to_path_buf),
            committed: false,
        }
    }

    pub(crate) fn push(&mut self, path: PathBuf, handle: OwnedHandle) {
        self.entries.push((path, handle));
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn commit(&mut self) {
        self.committed = true;
        self.entries.clear();
    }
}

impl Drop for PlaceholderRollbackGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        for (path, handle) in self.entries.iter().rev() {
            if let Err(reason) = delete_placeholder_if_empty(handle) {
                crate::logging::log_note(
                    &format!(
                        "placeholder rollback skipped for {}: {reason}",
                        path.display()
                    ),
                    self.logs_base_dir.as_deref(),
                );
            }
        }
    }
}

/// Creates a 0-byte placeholder named `file_name` inside `parent_handle`,
/// failing if anything already exists there.
pub(crate) fn create_placeholder_file(
    parent_handle: &OwnedHandle,
    file_name: &std::ffi::OsStr,
) -> Result<OwnedHandle> {
    let mut leaf_utf16: Vec<u16> = file_name.encode_wide().chain(Some(0)).collect();
    open_no_reparse(
        parent_handle.as_raw_handle() as HANDLE,
        &mut leaf_utf16,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
    )
}

fn delete_placeholder_if_empty(handle: &OwnedHandle) -> std::result::Result<(), String> {
    // Fails with a sharing violation while another opener holds the file
    // without FILE_SHARE_DELETE; keeping the file is the safe outcome then.
    let raw = unsafe {
        ReOpenFile(
            handle.as_raw_handle() as HANDLE,
            DELETE | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0,
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(format!(
            "reopen for delete failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let delete_handle = unsafe { OwnedHandle::from_raw_handle(raw as _) };

    let mut file_info = std::mem::MaybeUninit::<FILE_STANDARD_INFO>::uninit();
    let ok = unsafe {
        GetFileInformationByHandleEx(
            delete_handle.as_raw_handle() as HANDLE,
            FileStandardInfo,
            file_info.as_mut_ptr().cast(),
            std::mem::size_of::<FILE_STANDARD_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(format!(
            "size query failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let file_info = unsafe { file_info.assume_init() };
    if file_info.EndOfFile != 0 {
        return Err(format!("file non-empty (size={})", file_info.EndOfFile));
    }

    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    let ok = unsafe {
        SetFileInformationByHandle(
            delete_handle.as_raw_handle() as HANDLE,
            FileDispositionInfo,
            (&raw const disposition).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(format!(
            "delete failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

pub(crate) struct SpawnContext {
    pub(crate) permissions: ResolvedWindowsSandboxPermissions,
    pub(crate) current_dir: PathBuf,
    pub(crate) logs_base_dir: Option<PathBuf>,
    pub(crate) uses_write_capabilities: bool,
    pub(crate) placeholder_guard: PlaceholderRollbackGuard,
}

pub(crate) struct ElevatedSpawnContext {
    pub(crate) sandbox_base: PathBuf,
    pub(crate) logs_base_dir: Option<PathBuf>,
    pub(crate) sandbox_creds: SandboxCreds,
    pub(crate) cap_sids: Vec<String>,
    pub(crate) placeholder_guard: PlaceholderRollbackGuard,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SpawnPrepOptions {
    pub(crate) inherit_path: bool,
    pub(crate) add_git_safe_directory: bool,
}

pub(crate) struct LegacySessionSecurity {
    pub(crate) h_token: HANDLE,
    pub(crate) readonly_sid: Option<LocalSid>,
    pub(crate) readonly_sid_str: Option<String>,
    pub(crate) write_root_sids: Vec<RootCapabilitySid>,
}

pub(crate) struct RootCapabilitySid {
    pub(crate) root: PathBuf,
    pub(crate) sid: LocalSid,
    pub(crate) sid_str: String,
}

pub(crate) struct LegacyAclSids<'a> {
    pub(crate) readonly_sid: Option<&'a LocalSid>,
    pub(crate) readonly_sid_str: Option<&'a str>,
    pub(crate) write_root_sids: &'a [RootCapabilitySid],
}

/// Creates 0-byte placeholders for explicit write grants that do not exist yet,
/// so the exact-file ACE can attach without granting anything on the parent.
///
/// `writable_roots` must return the roots this launch actually grants ACLs on;
/// it is only called when there is a candidate. A candidate whose parent is
/// already one of those roots (and not denied) is left for the child to create,
/// as a file or a directory.
#[allow(clippy::too_many_arguments)]
pub(crate) fn materialize_missing_write_target_placeholders(
    permissions: &ResolvedWindowsSandboxPermissions,
    cwd: &Path,
    env_map: &HashMap<String, String>,
    codex_home: &Path,
    additional_deny_write_paths: &[PathBuf],
    logs_base_dir: Option<&Path>,
    writable_roots: impl FnOnce() -> Vec<PathBuf>,
) -> PlaceholderRollbackGuard {
    let mut guard = PlaceholderRollbackGuard::new(logs_base_dir);
    let candidates = permissions.explicit_missing_write_target_candidates(cwd);
    if candidates.is_empty() {
        return guard;
    }
    let writable_dirs: Vec<PathBuf> = writable_roots()
        .into_iter()
        .filter(|root| root.is_dir())
        .collect();
    let mut deny_paths: Vec<PathBuf> =
        compute_allow_paths_for_permissions(permissions, cwd, env_map)
            .deny
            .into_iter()
            .collect();
    deny_paths.extend(additional_deny_write_paths.iter().cloned());

    for candidate in candidates {
        if candidate.symlink_metadata().is_ok() {
            continue;
        }
        let candidate_key = canonical_path_key(&candidate);
        if additional_deny_write_paths
            .iter()
            .any(|deny| canonical_path_key(deny) == candidate_key)
        {
            continue;
        }
        if !crate::setup::is_allowed_write_target_path(&candidate, codex_home) {
            continue;
        }
        if validate_local_directory_path(&candidate).is_err() {
            continue;
        }
        let Some(parent) = candidate.parent() else {
            continue;
        };
        let Some(file_name) = candidate.file_name() else {
            continue;
        };
        if parent.symlink_metadata().is_err() {
            continue;
        }
        // Inside a denied directory the grant must not become writable; inside a
        // writable root the child can create it itself. Either way, no placeholder.
        if deny_paths
            .iter()
            .any(|deny| workspace_write_root_contains_path(deny, parent))
        {
            continue;
        }
        if writable_dirs
            .iter()
            .any(|root| workspace_write_root_contains_path(root, parent))
        {
            continue;
        }
        let parent_handle = match open_directory_no_reparse(
            parent,
            FILE_TRAVERSE | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            DirectoryOpenDisposition::OpenExisting,
        ) {
            Ok(handle) => handle,
            Err(err) => {
                crate::logging::log_note(
                    &format!(
                        "placeholder parent open failed for {}: {err}",
                        candidate.display()
                    ),
                    logs_base_dir,
                );
                continue;
            }
        };

        match create_placeholder_file(&parent_handle, file_name) {
            Ok(handle) => {
                guard.push(candidate, handle);
            }
            Err(err) => {
                crate::logging::log_note(
                    &format!(
                        "placeholder creation skipped for {}: {err}",
                        candidate.display()
                    ),
                    logs_base_dir,
                );
            }
        }
    }
    guard
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_spawn_context_common(
    permission_profile: &PermissionProfile,
    workspace_roots: &[AbsolutePathBuf],
    codex_home: &Path,
    cwd: &Path,
    env_map: &mut HashMap<String, String>,
    command: &[String],
    additional_deny_write_paths: &[PathBuf],
    options: SpawnPrepOptions,
) -> Result<SpawnContext> {
    let permissions =
        ResolvedWindowsSandboxPermissions::try_from_permission_profile_for_workspace_roots(
            permission_profile,
            workspace_roots,
        )?;

    normalize_null_device_env(env_map);
    ensure_non_interactive_pager(env_map);
    if options.inherit_path {
        inherit_path_env(env_map);
    }
    if options.add_git_safe_directory {
        inject_git_safe_directory(env_map, cwd);
    }

    ensure_codex_home_exists(codex_home)?;
    let sandbox_base = codex_home.join(".sandbox");
    std::fs::create_dir_all(&sandbox_base)?;
    let logs_base_dir = Some(sandbox_base);
    log_start(command, logs_base_dir.as_deref());

    let env_map: &HashMap<String, String> = env_map;
    let placeholder_guard = materialize_missing_write_target_placeholders(
        &permissions,
        cwd,
        env_map,
        codex_home,
        additional_deny_write_paths,
        logs_base_dir.as_deref(),
        || legacy_session_capability_roots(&permissions, cwd, env_map, codex_home),
    );

    let uses_write_capabilities = permissions.uses_write_capabilities_for_cwd(cwd, env_map);

    Ok(SpawnContext {
        permissions,
        current_dir: cwd.to_path_buf(),
        logs_base_dir,
        uses_write_capabilities,
        placeholder_guard,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_legacy_spawn_context(
    permission_profile: &PermissionProfile,
    workspace_roots: &[AbsolutePathBuf],
    codex_home: &Path,
    cwd: &Path,
    env_map: &mut HashMap<String, String>,
    command: &[String],
    additional_deny_write_paths: &[PathBuf],
    options: SpawnPrepOptions,
) -> Result<SpawnContext> {
    let common = prepare_spawn_context_common(
        permission_profile,
        workspace_roots,
        codex_home,
        cwd,
        env_map,
        command,
        additional_deny_write_paths,
        options,
    )?;
    if common.permissions.should_apply_network_block() {
        apply_no_network_to_env(env_map)?;
    }
    Ok(common)
}

pub(crate) fn prepare_legacy_session_security(
    uses_write_capabilities: bool,
    codex_home: &Path,
    cwd: &Path,
    capability_roots: impl IntoIterator<Item = PathBuf>,
) -> Result<LegacySessionSecurity> {
    let caps = load_or_create_cap_sids(codex_home)?;
    let (h_token, readonly_sid, readonly_sid_str, write_root_sids) = unsafe {
        if uses_write_capabilities {
            let write_root_sids = root_capability_sids(codex_home, cwd, capability_roots)?;
            if write_root_sids.is_empty() {
                anyhow::bail!("workspace-write sandbox has no writable root capability SIDs");
            }
            let base = get_current_token_for_restriction()?;
            let cap_ptrs: Vec<*mut c_void> = write_root_sids
                .iter()
                .map(|root| root.sid.as_ptr())
                .collect();
            let h_token = create_workspace_write_token_with_caps_from(base, cap_ptrs.as_slice());
            CloseHandle(base);
            let h_token = h_token?;
            (h_token, None, None, write_root_sids)
        } else {
            let psid = LocalSid::from_string(&caps.readonly)?;
            let (h_token, _psid) = create_readonly_token_with_cap(psid.as_ptr())?;
            (h_token, Some(psid), Some(caps.readonly), Vec::new())
        }
    };

    Ok(LegacySessionSecurity {
        h_token,
        readonly_sid,
        readonly_sid_str,
        write_root_sids,
    })
}

pub(crate) fn legacy_session_capability_roots(
    permissions: &ResolvedWindowsSandboxPermissions,
    current_dir: &Path,
    env_map: &HashMap<String, String>,
    codex_home: &Path,
) -> Vec<PathBuf> {
    let allow_paths = compute_allow_paths_for_permissions(permissions, current_dir, env_map)
        .allow
        .into_iter()
        .collect::<Vec<_>>();
    if permissions.uses_write_capabilities_for_cwd(current_dir, env_map) {
        effective_write_roots_for_permissions(
            permissions,
            current_dir,
            env_map,
            codex_home,
            Some(allow_paths.as_slice()),
        )
    } else {
        allow_paths
    }
}

pub(crate) fn root_capability_sids(
    codex_home: &Path,
    cwd: &Path,
    allow_paths: impl IntoIterator<Item = PathBuf>,
) -> Result<Vec<RootCapabilitySid>> {
    let mut roots: Vec<PathBuf> = allow_paths.into_iter().collect();
    roots.sort_by_key(|root| canonicalize_path(root.as_path()));
    roots.dedup_by(|a, b| canonicalize_path(a.as_path()) == canonicalize_path(b.as_path()));

    let mut out = Vec::with_capacity(roots.len());
    for root in roots {
        let sid_str = workspace_write_cap_sid_for_root(codex_home, cwd, &root)?;
        let sid = LocalSid::from_string(&sid_str)?;
        out.push(RootCapabilitySid { root, sid, sid_str });
    }
    Ok(out)
}

fn matching_root_capability<'a>(
    path: &Path,
    root_sids: &'a [RootCapabilitySid],
) -> Option<&'a RootCapabilitySid> {
    root_sids
        .iter()
        .filter(|root_sid| workspace_write_root_contains_path(&root_sid.root, path))
        .max_by_key(|root_sid| workspace_write_root_specificity(&root_sid.root))
}

fn deny_root_capabilities_for_path<'a>(
    path: &Path,
    root_sids: &'a [RootCapabilitySid],
) -> Vec<&'a RootCapabilitySid> {
    let matching_root_sids = root_sids
        .iter()
        .filter(|root_sid| workspace_write_root_overlaps_path(&root_sid.root, path))
        .collect::<Vec<_>>();
    if matching_root_sids.is_empty() {
        root_sids.iter().collect()
    } else {
        matching_root_sids
    }
}

pub(crate) fn allow_null_device_for_workspace_write(is_workspace_write: bool) {
    if !is_workspace_write {
        return;
    }

    unsafe {
        if let Ok(base) = get_current_token_for_restriction() {
            if let Ok(bytes) = get_logon_sid_bytes(base) {
                let mut tmp = bytes;
                let psid = tmp.as_mut_ptr() as *mut c_void;
                allow_null_device(psid);
            }
            CloseHandle(base);
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_legacy_session_acl_rules(
    permissions: &ResolvedWindowsSandboxPermissions,
    codex_home: &Path,
    current_dir: &Path,
    env_map: &HashMap<String, String>,
    additional_deny_read_paths: &[PathBuf],
    additional_deny_write_paths: &[PathBuf],
    acl_sids: LegacyAclSids<'_>,
) -> Result<()> {
    let AllowDenyPaths { allow, mut deny } =
        compute_allow_paths_for_permissions(permissions, current_dir, env_map);
    unsafe {
        for path in additional_deny_write_paths {
            // Explicit carveouts must exist before the command starts so the
            // sandbox cannot create them under a writable parent first.
            if !path.exists() {
                std::fs::create_dir_all(path)
                    .with_context(|| format!("create deny-write path {}", path.display()))?;
            }
            deny.insert(path.clone());
        }
        if let Some(readonly_sid) = acl_sids.readonly_sid {
            for p in &allow {
                let _ = add_allow_ace(p, readonly_sid.as_ptr());
            }
        } else {
            for p in &allow {
                let Some(root_sid) = matching_root_capability(p, acl_sids.write_root_sids) else {
                    continue;
                };
                let _ = ensure_allow_write_aces(p, &[root_sid.sid.as_ptr()]);
            }
        }
        for p in &deny {
            for root_sid in deny_root_capabilities_for_path(p, acl_sids.write_root_sids) {
                let _ = add_deny_write_ace(p, root_sid.sid.as_ptr());
            }
        }
        if !additional_deny_read_paths.is_empty() {
            if let Some(readonly_sid) = acl_sids.readonly_sid {
                let Some(readonly_sid_str) = acl_sids.readonly_sid_str else {
                    anyhow::bail!("readonly capability SID string missing");
                };
                sync_persistent_deny_read_acls(
                    codex_home,
                    readonly_sid_str,
                    additional_deny_read_paths,
                    readonly_sid.as_ptr(),
                )?;
            } else {
                for root_sid in acl_sids.write_root_sids {
                    sync_persistent_deny_read_acls(
                        codex_home,
                        &root_sid.sid_str,
                        additional_deny_read_paths,
                        root_sid.sid.as_ptr(),
                    )?;
                }
            }
        }
        for root_sid in acl_sids.write_root_sids {
            allow_null_device(root_sid.sid.as_ptr());
        }
        if let Some(readonly_sid) = acl_sids.readonly_sid {
            allow_null_device(readonly_sid.as_ptr());
        }
        if !acl_sids.write_root_sids.is_empty()
            && let Some(workspace_sid) =
                matching_root_capability(current_dir, acl_sids.write_root_sids)
        {
            let canonical_cwd = canonicalize_path(current_dir);
            if is_command_cwd_root(&workspace_sid.root, &canonical_cwd) {
                let _ = protect_workspace_codex_dir(current_dir, workspace_sid.sid.as_ptr());
                let _ = protect_workspace_agents_dir(current_dir, workspace_sid.sid.as_ptr());
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_elevated_spawn_context_for_permissions(
    permissions: ResolvedWindowsSandboxPermissions,
    codex_home: &Path,
    cwd: &Path,
    env_map: &mut HashMap<String, String>,
    command: &[String],
    read_roots_override: Option<&[PathBuf]>,
    read_roots_include_platform_defaults: bool,
    write_roots_override: Option<&[PathBuf]>,
    deny_read_paths_override: &[PathBuf],
    deny_write_paths_override: &[PathBuf],
    proxy_enforced: bool,
    proxy_settings_mode: crate::WindowsSandboxProxySettingsMode,
) -> Result<ElevatedSpawnContext> {
    normalize_null_device_env(env_map);
    ensure_non_interactive_pager(env_map);
    inherit_path_env(env_map);
    inject_git_safe_directory(env_map, cwd);

    // Use a temp-based log dir that the sandbox user can write.
    let sandbox_base = codex_home.join(".sandbox");
    ensure_codex_home_exists(&sandbox_base)?;
    let logs_base_dir = Some(sandbox_base.clone());
    log_start(command, logs_base_dir.as_deref());

    // Same roots this launch hands to setup below.
    let placeholder_guard = materialize_missing_write_target_placeholders(
        &permissions,
        cwd,
        env_map,
        codex_home,
        deny_write_paths_override,
        logs_base_dir.as_deref(),
        || {
            if !permissions.uses_write_capabilities_for_cwd(cwd, env_map) {
                return Vec::new();
            }
            let allow: Vec<PathBuf> =
                compute_allow_paths_for_permissions(&permissions, cwd, env_map)
                    .allow
                    .into_iter()
                    .collect();
            effective_write_roots_for_permissions(
                &permissions,
                cwd,
                env_map,
                codex_home,
                write_roots_override.or(Some(allow.as_slice())),
            )
        },
    );

    let uses_write_capabilities = permissions.uses_write_capabilities_for_cwd(cwd, env_map);

    let AllowDenyPaths { allow, deny } =
        compute_allow_paths_for_permissions(&permissions, cwd, env_map);
    let write_roots: Vec<PathBuf> = allow.into_iter().collect();
    let deny_write_paths: Vec<PathBuf> = deny.into_iter().collect();
    let computed_write_roots_override = if uses_write_capabilities {
        Some(write_roots.as_slice())
    } else {
        None
    };
    let write_roots_for_setup = write_roots_override.or(computed_write_roots_override);
    let effective_write_roots = if uses_write_capabilities {
        effective_write_roots_for_permissions(
            &permissions,
            cwd,
            env_map,
            codex_home,
            write_roots_for_setup,
        )
    } else {
        Vec::new()
    };
    let setup_write_roots_override = if uses_write_capabilities {
        Some(effective_write_roots.as_slice())
    } else {
        write_roots_override
    };
    let sandbox_creds = require_logon_sandbox_creds(
        &permissions,
        cwd,
        env_map,
        codex_home,
        read_roots_override,
        read_roots_include_platform_defaults,
        setup_write_roots_override,
        deny_read_paths_override,
        if deny_write_paths_override.is_empty() {
            &deny_write_paths
        } else {
            deny_write_paths_override
        },
        proxy_enforced,
        proxy_settings_mode,
    )?;
    let caps = load_or_create_cap_sids(codex_home)?;
    let (psid_to_use, cap_sids) = if uses_write_capabilities {
        let cap_sids = root_capability_sids(codex_home, cwd, effective_write_roots)?
            .into_iter()
            .map(|root_sid| root_sid.sid_str)
            .collect::<Vec<_>>();
        if cap_sids.is_empty() {
            anyhow::bail!("workspace-write sandbox has no writable root capability SIDs");
        }
        (LocalSid::from_string(&cap_sids[0])?, cap_sids)
    } else {
        (
            LocalSid::from_string(&caps.readonly)?,
            vec![caps.readonly.clone()],
        )
    };

    unsafe {
        allow_null_device(psid_to_use.as_ptr());
    }

    Ok(ElevatedSpawnContext {
        sandbox_base,
        logs_base_dir,
        sandbox_creds,
        cap_sids,
        placeholder_guard,
    })
}

#[cfg(test)]
mod tests {
    use super::FILE_READ_ATTRIBUTES;
    use super::FILE_SHARE_READ;
    use super::FILE_SHARE_WRITE;
    use super::FILE_TRAVERSE;
    use super::PlaceholderRollbackGuard;
    use super::SpawnPrepOptions;
    use super::create_placeholder_file;
    use super::deny_root_capabilities_for_path;
    use super::legacy_session_capability_roots;
    use super::materialize_missing_write_target_placeholders;
    use super::prepare_legacy_spawn_context;
    use super::prepare_spawn_context_common;
    use super::root_capability_sids;
    use crate::cap::load_or_create_cap_sids;
    use crate::cap::workspace_write_cap_sid_for_root;
    use crate::no_reparse_dir::DirectoryOpenDisposition;
    use crate::no_reparse_dir::open_directory_no_reparse;
    use crate::resolved_permissions::ResolvedWindowsSandboxPermissions;
    use codex_protocol::models::PermissionProfile;
    use codex_protocol::permissions::NetworkSandboxPolicy;
    use codex_utils_absolute_path::AbsolutePathBuf;
    use pretty_assertions::assert_eq;
    use std::collections::HashMap;
    use std::os::windows::fs::OpenOptionsExt;
    use std::path::Path;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn workspace_profile(
        network_policy: NetworkSandboxPolicy,
        writable_roots: &[AbsolutePathBuf],
        exclude_tmpdir_env_var: bool,
        exclude_slash_tmp: bool,
    ) -> PermissionProfile {
        PermissionProfile::workspace_write_with(
            writable_roots,
            network_policy,
            exclude_tmpdir_env_var,
            exclude_slash_tmp,
        )
    }

    fn workspace_roots_for(root: &Path) -> Vec<AbsolutePathBuf> {
        vec![AbsolutePathBuf::from_absolute_path(root).expect("absolute workspace root")]
    }

    fn should_apply_network_block(permission_profile: &PermissionProfile) -> bool {
        ResolvedWindowsSandboxPermissions::try_from_permission_profile_for_workspace_roots(
            permission_profile,
            &[],
        )
        .expect("managed permission profile")
        .should_apply_network_block()
    }

    #[test]
    fn no_network_env_rewrite_applies_for_workspace_write() {
        assert!(should_apply_network_block(
            &PermissionProfile::workspace_write()
        ));
    }

    #[test]
    fn no_network_env_rewrite_skips_when_network_access_is_allowed() {
        assert!(!should_apply_network_block(&workspace_profile(
            NetworkSandboxPolicy::Enabled,
            &[],
            /*exclude_tmpdir_env_var*/ false,
            /*exclude_slash_tmp*/ false,
        )));
    }

    #[test]
    fn legacy_spawn_env_applies_offline_network_rewrite() {
        let codex_home = TempDir::new().expect("tempdir");
        let cwd = TempDir::new().expect("tempdir");
        let mut env_map = HashMap::new();
        let workspace_roots = workspace_roots_for(cwd.path());

        let _context = prepare_legacy_spawn_context(
            &PermissionProfile::workspace_write(),
            workspace_roots.as_slice(),
            codex_home.path(),
            cwd.path(),
            &mut env_map,
            &["cmd.exe".to_string()],
            &[],
            SpawnPrepOptions {
                inherit_path: true,
                add_git_safe_directory: false,
            },
        )
        .expect("legacy env prep");

        assert_eq!(env_map.get("SBX_NONET_ACTIVE"), Some(&"1".to_string()));
        assert_eq!(
            env_map.get("HTTP_PROXY"),
            Some(&"http://127.0.0.1:9".to_string())
        );
    }

    #[test]
    fn common_spawn_env_keeps_network_env_unchanged() {
        let codex_home = TempDir::new().expect("tempdir");
        let cwd = TempDir::new().expect("tempdir");
        let mut env_map = HashMap::from([(
            "HTTP_PROXY".to_string(),
            "http://user.proxy:8080".to_string(),
        )]);
        let workspace_roots = workspace_roots_for(cwd.path());

        let context = prepare_spawn_context_common(
            &PermissionProfile::workspace_write(),
            workspace_roots.as_slice(),
            codex_home.path(),
            cwd.path(),
            &mut env_map,
            &["cmd.exe".to_string()],
            &[],
            SpawnPrepOptions {
                inherit_path: true,
                add_git_safe_directory: true,
            },
        )
        .expect("preserve existing env prep");
        assert!(context.uses_write_capabilities);

        assert_eq!(env_map.get("SBX_NONET_ACTIVE"), None);
        assert_eq!(
            env_map.get("HTTP_PROXY"),
            Some(&"http://user.proxy:8080".to_string())
        );
    }

    #[test]
    fn legacy_session_capability_roots_use_runtime_workspace_roots_for_workspace_root() {
        let tmp = TempDir::new().expect("tempdir");
        let codex_home = tmp.path().join("codex-home");
        let workspace_root = tmp.path().join("workspace");
        let command_cwd = workspace_root.join("subdir");
        std::fs::create_dir_all(&codex_home).expect("create codex home");
        std::fs::create_dir_all(&command_cwd).expect("create command cwd");

        let permission_profile = workspace_profile(
            NetworkSandboxPolicy::Restricted,
            &[],
            /*exclude_tmpdir_env_var*/ true,
            /*exclude_slash_tmp*/ true,
        );
        let workspace_roots = workspace_roots_for(workspace_root.as_path());
        let permissions =
            ResolvedWindowsSandboxPermissions::try_from_permission_profile_for_workspace_roots(
                &permission_profile,
                workspace_roots.as_slice(),
            )
            .expect("managed permission profile");

        let roots = legacy_session_capability_roots(
            &permissions,
            &command_cwd,
            &HashMap::new(),
            &codex_home,
        );

        assert_eq!(
            roots,
            vec![dunce::canonicalize(&workspace_root).expect("canonical workspace root")]
        );
    }

    #[test]
    fn root_capability_sids_only_include_active_roots() {
        let temp = TempDir::new().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let workspace = temp.path().join("workspace");
        let active_root = temp.path().join("active-root");
        let stale_root = temp.path().join("stale-root");
        std::fs::create_dir_all(&codex_home).expect("create codex home");
        std::fs::create_dir_all(&workspace).expect("create workspace");
        std::fs::create_dir_all(&active_root).expect("create active root");
        std::fs::create_dir_all(&stale_root).expect("create stale root");

        let stale_sid = workspace_write_cap_sid_for_root(&codex_home, &workspace, &stale_root)
            .expect("stale sid");
        let active_sid = workspace_write_cap_sid_for_root(&codex_home, &workspace, &active_root)
            .expect("active sid");
        let workspace_sid = workspace_write_cap_sid_for_root(&codex_home, &workspace, &workspace)
            .expect("workspace sid");
        let caps = load_or_create_cap_sids(&codex_home).expect("load caps");

        let sid_strs = root_capability_sids(
            &codex_home,
            &workspace,
            vec![workspace.clone(), active_root],
        )
        .expect("root capabilities")
        .into_iter()
        .map(|root_sid| root_sid.sid_str)
        .collect::<Vec<_>>();

        assert_eq!(sid_strs.len(), 2);
        assert!(sid_strs.contains(&workspace_sid));
        assert!(sid_strs.contains(&active_sid));
        assert!(!sid_strs.contains(&stale_sid));
        assert!(!sid_strs.contains(&caps.workspace));
    }

    #[test]
    fn legacy_deny_path_includes_nested_active_root_sid() {
        let temp = TempDir::new().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let workspace = temp.path().join("workspace");
        let protected_dir = workspace.join(".codex");
        let nested_root = protected_dir.join("nested-root");
        let unrelated_root = temp.path().join("unrelated-root");
        std::fs::create_dir_all(&codex_home).expect("create codex home");
        std::fs::create_dir_all(&workspace).expect("create workspace");
        std::fs::create_dir_all(&nested_root).expect("create nested root");
        std::fs::create_dir_all(&unrelated_root).expect("create unrelated root");

        let workspace_sid = workspace_write_cap_sid_for_root(&codex_home, &workspace, &workspace)
            .expect("workspace sid");
        let nested_sid = workspace_write_cap_sid_for_root(&codex_home, &workspace, &nested_root)
            .expect("nested sid");
        let unrelated_sid =
            workspace_write_cap_sid_for_root(&codex_home, &workspace, &unrelated_root)
                .expect("unrelated sid");
        let root_sids = root_capability_sids(
            &codex_home,
            &workspace,
            vec![workspace.clone(), nested_root, unrelated_root],
        )
        .expect("root capabilities");

        let deny_sid_strs = deny_root_capabilities_for_path(&protected_dir, &root_sids)
            .into_iter()
            .map(|root_sid| root_sid.sid_str.clone())
            .collect::<Vec<_>>();

        assert_eq!(deny_sid_strs, vec![workspace_sid, nested_sid]);
        assert!(!deny_sid_strs.contains(&unrelated_sid));
    }

    #[test]
    fn legacy_capability_roots_use_effective_write_roots() {
        let temp = TempDir::new().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let workspace = temp.path().join("workspace");
        let active_root = temp.path().join("active-root");
        let sandbox_root = codex_home.join(".sandbox");
        std::fs::create_dir_all(&codex_home).expect("create codex home");
        std::fs::create_dir_all(&workspace).expect("create workspace");
        std::fs::create_dir_all(&active_root).expect("create active root");
        std::fs::create_dir_all(&sandbox_root).expect("create sandbox root");

        let writable_roots = vec![
            AbsolutePathBuf::try_from(active_root.as_path()).expect("active root"),
            AbsolutePathBuf::try_from(codex_home.as_path()).expect("codex home"),
            AbsolutePathBuf::try_from(sandbox_root.as_path()).expect("sandbox root"),
        ];
        let permission_profile = workspace_profile(
            NetworkSandboxPolicy::Restricted,
            &writable_roots,
            /*exclude_tmpdir_env_var*/ true,
            /*exclude_slash_tmp*/ true,
        );
        let workspace_roots = workspace_roots_for(workspace.as_path());
        let permissions =
            ResolvedWindowsSandboxPermissions::try_from_permission_profile_for_workspace_roots(
                &permission_profile,
                workspace_roots.as_slice(),
            )
            .expect("managed permission profile");

        let roots =
            legacy_session_capability_roots(&permissions, &workspace, &HashMap::new(), &codex_home);

        assert!(roots.contains(&dunce::canonicalize(&workspace).expect("workspace")));
        assert!(roots.contains(&dunce::canonicalize(&active_root).expect("active root")));
        assert!(!roots.contains(&dunce::canonicalize(&codex_home).expect("codex home")));
        assert!(!roots.contains(&dunce::canonicalize(&sandbox_root).expect("sandbox root")));
    }

    /// Creates `name` in `dir` the way materialization does and arms a guard for it.
    fn guarded_placeholder(dir: &Path, name: &str) -> (PathBuf, PlaceholderRollbackGuard) {
        let parent_handle = open_directory_no_reparse(
            dir,
            FILE_TRAVERSE | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            DirectoryOpenDisposition::OpenExisting,
        )
        .expect("open parent");
        let handle = create_placeholder_file(&parent_handle, std::ffi::OsStr::new(name))
            .expect("create placeholder");
        let path = dir.join(name);
        let mut guard = PlaceholderRollbackGuard::new(None);
        guard.push(path.clone(), handle);
        (path, guard)
    }

    fn open_without_share_delete(path: &Path) -> std::fs::File {
        std::fs::OpenOptions::new()
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(path)
            .expect("open without FILE_SHARE_DELETE")
    }

    #[test]
    fn placeholder_guard_rollback_deletes_zero_byte_file_on_drop() {
        let tmp = TempDir::new().expect("tempdir");
        let (path, guard) = guarded_placeholder(tmp.path(), "placeholder.txt");
        assert_eq!(std::fs::metadata(&path).expect("placeholder").len(), 0);

        drop(guard);

        assert!(
            !path.exists(),
            "uncommitted 0-byte placeholder must be deleted"
        );
    }

    #[test]
    fn placeholder_guard_rollback_preserves_non_empty_file_on_drop() {
        let tmp = TempDir::new().expect("tempdir");
        let (path, guard) = guarded_placeholder(tmp.path(), "placeholder_with_data.txt");
        std::fs::write(&path, "important user data").expect("write user data");

        drop(guard);

        assert_eq!(
            std::fs::read_to_string(&path).expect("file kept"),
            "important user data"
        );
    }

    #[test]
    fn placeholder_guard_commit_preserves_file_and_closes_handles() {
        let tmp = TempDir::new().expect("tempdir");
        let (path, mut guard) = guarded_placeholder(tmp.path(), "committed.txt");

        guard.commit();
        assert!(guard.is_empty(), "commit must close handles");
        drop(guard);

        assert!(path.exists(), "committed placeholder must stay on disk");
    }

    #[test]
    fn placeholder_guard_does_not_block_openers_without_share_delete() {
        // Many writers (MSVC CRT fopen, Office) omit FILE_SHARE_DELETE. The
        // guard's handle must not make them fail with a sharing violation.
        let tmp = TempDir::new().expect("tempdir");
        let (path, guard) = guarded_placeholder(tmp.path(), "shared.txt");

        let file = open_without_share_delete(&path);
        drop(file);
        drop(guard);

        assert!(!path.exists(), "still-empty placeholder is rolled back");
    }

    #[test]
    fn placeholder_guard_keeps_file_another_process_holds_open() {
        let tmp = TempDir::new().expect("tempdir");
        let (path, guard) = guarded_placeholder(tmp.path(), "held.txt");

        let file = open_without_share_delete(&path);
        drop(guard);

        assert!(path.exists(), "rollback must not delete a file in use");
        drop(file);
    }

    #[test]
    fn materialize_placeholders_skips_missing_parent() {
        let tmp = TempDir::new().expect("tempdir");
        let cwd = tmp.path().join("work");
        let codex_home = tmp.path().join("codex-home");
        std::fs::create_dir_all(&cwd).expect("create cwd");
        std::fs::create_dir_all(&codex_home).expect("create codex home");

        let non_existent_parent = tmp.path().join("missing_parent");
        let target = non_existent_parent.join("file.txt");

        let profile = PermissionProfile::Managed {
            file_system: codex_protocol::models::ManagedFileSystemPermissions::Restricted {
                entries: vec![
                    codex_protocol::permissions::FileSystemSandboxEntry::new(
                        codex_protocol::permissions::FileSystemPath::Special {
                            value: codex_protocol::permissions::FileSystemSpecialPath::Root,
                        },
                        codex_protocol::permissions::FileSystemAccessMode::Read,
                    ),
                    codex_protocol::permissions::FileSystemSandboxEntry::new(
                        codex_protocol::permissions::FileSystemPath::Path {
                            path: AbsolutePathBuf::from_absolute_path(&target).unwrap().into(),
                        },
                        codex_protocol::permissions::FileSystemAccessMode::Write,
                    ),
                ],
                glob_scan_max_depth: None,
            },
            network: codex_protocol::permissions::NetworkSandboxPolicy::Restricted,
        };
        let permissions =
            ResolvedWindowsSandboxPermissions::try_from_permission_profile(&profile).unwrap();

        let guard = materialize_missing_write_target_placeholders(
            &permissions,
            &cwd,
            &HashMap::new(),
            &codex_home,
            &[],
            None,
            Vec::new,
        );
        assert!(
            guard.is_empty(),
            "missing parent directory must be skipped without creating parent"
        );
        assert!(
            !non_existent_parent.exists(),
            "parent directory must not be created"
        );
        assert!(!target.exists(), "target must not be created");
    }

    #[test]
    fn materialize_placeholders_preserves_existing_file() {
        let tmp = TempDir::new().expect("tempdir");
        let cwd = tmp.path().join("work");
        let codex_home = tmp.path().join("codex-home");
        std::fs::create_dir_all(&cwd).expect("create cwd");
        std::fs::create_dir_all(&codex_home).expect("create codex home");

        let existing_file = tmp.path().join("existing.txt");
        std::fs::write(&existing_file, "existing file content").expect("write existing");

        let profile = PermissionProfile::Managed {
            file_system: codex_protocol::models::ManagedFileSystemPermissions::Restricted {
                entries: vec![
                    codex_protocol::permissions::FileSystemSandboxEntry::new(
                        codex_protocol::permissions::FileSystemPath::Special {
                            value: codex_protocol::permissions::FileSystemSpecialPath::Root,
                        },
                        codex_protocol::permissions::FileSystemAccessMode::Read,
                    ),
                    codex_protocol::permissions::FileSystemSandboxEntry::new(
                        codex_protocol::permissions::FileSystemPath::Path {
                            path: AbsolutePathBuf::from_absolute_path(&existing_file)
                                .unwrap()
                                .into(),
                        },
                        codex_protocol::permissions::FileSystemAccessMode::Write,
                    ),
                ],
                glob_scan_max_depth: None,
            },
            network: codex_protocol::permissions::NetworkSandboxPolicy::Restricted,
        };
        let permissions =
            ResolvedWindowsSandboxPermissions::try_from_permission_profile(&profile).unwrap();

        let guard = materialize_missing_write_target_placeholders(
            &permissions,
            &cwd,
            &HashMap::new(),
            &codex_home,
            &[],
            None,
            Vec::new,
        );
        assert!(
            guard.is_empty(),
            "existing file must not be added to rollback guard"
        );
        assert_eq!(
            std::fs::read_to_string(&existing_file).unwrap(),
            "existing file content"
        );
    }

    fn absolute(path: &Path) -> AbsolutePathBuf {
        AbsolutePathBuf::from_absolute_path(path).expect("absolute path")
    }

    /// Materializes with the same roots a legacy launch grants ACLs on.
    fn materialize_with_legacy_roots(
        profile: &PermissionProfile,
        workspace: &Path,
        env_map: &HashMap<String, String>,
        codex_home: &Path,
        additional_deny_write_paths: &[PathBuf],
    ) -> PlaceholderRollbackGuard {
        let permissions =
            ResolvedWindowsSandboxPermissions::try_from_permission_profile_for_workspace_roots(
                profile,
                workspace_roots_for(workspace).as_slice(),
            )
            .expect("managed permission profile");
        materialize_missing_write_target_placeholders(
            &permissions,
            workspace,
            env_map,
            codex_home,
            additional_deny_write_paths,
            None,
            || legacy_session_capability_roots(&permissions, workspace, env_map, codex_home),
        )
    }

    #[test]
    fn materialize_placeholders_n6_effective_parent_matrix() {
        let tmp = TempDir::new().expect("tempdir");
        let workspace = tmp.path().join("workspace");
        let codex_home = tmp.path().join("codex-home");
        let temp_dir = tmp.path().join("temp");
        let protected = workspace.join("protected");
        let outside = tmp.path().join("outside");
        for dir in [&workspace, &codex_home, &temp_dir, &protected, &outside] {
            std::fs::create_dir_all(dir).expect("create dir");
        }
        let workspace_out = workspace.join("out");
        let temp_out = temp_dir.join("out");
        let denied_new = protected.join("new.txt");
        let outside_new = outside.join("new.txt");

        let profile = workspace_profile(
            NetworkSandboxPolicy::Restricted,
            &[
                absolute(&workspace_out),
                absolute(&temp_out),
                absolute(&denied_new),
                absolute(&outside_new),
            ],
            /*exclude_tmpdir_env_var*/ false,
            /*exclude_slash_tmp*/ true,
        );
        let env_map = HashMap::from([
            ("TEMP".to_string(), temp_dir.display().to_string()),
            ("TMP".to_string(), temp_dir.display().to_string()),
        ]);

        let guard = materialize_with_legacy_roots(
            &profile,
            &workspace,
            &env_map,
            &codex_home,
            std::slice::from_ref(&protected),
        );

        assert!(
            !workspace_out.exists(),
            "creatable under the writable workspace"
        );
        assert!(!temp_out.exists(), "creatable under TEMP from env_map");
        assert!(!denied_new.exists(), "inside a denied directory");
        assert!(
            outside_new.is_file(),
            "outside every writable root gets a placeholder"
        );

        drop(guard);
        assert!(
            !outside_new.exists(),
            "uncommitted placeholder is rolled back"
        );
    }

    #[test]
    fn materialize_placeholders_targets_user_profile_children_when_cwd_is_user_profile() {
        // Windows strips USERPROFILE itself from writable roots, so a missing
        // file directly under it is not creatable by the child even when the
        // policy marks cwd == USERPROFILE writable (openai/codex#58433 RF-1).
        let Some(user_profile) = std::env::var_os("USERPROFILE").map(PathBuf::from) else {
            return;
        };
        let codex_home = TempDir::new().expect("tempdir");
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let target = user_profile.join(format!(
            "codex-58433-placeholder-{}-{nonce}.txt",
            std::process::id()
        ));
        assert!(!target.exists());
        let profile = workspace_profile(
            NetworkSandboxPolicy::Restricted,
            &[absolute(&target)],
            /*exclude_tmpdir_env_var*/ true,
            /*exclude_slash_tmp*/ true,
        );

        let guard = materialize_with_legacy_roots(
            &profile,
            &user_profile,
            &HashMap::new(),
            codex_home.path(),
            &[],
        );

        assert!(
            target.is_file(),
            "placeholder must be created under USERPROFILE"
        );
        drop(guard);
        assert!(!target.exists(), "rollback removes the test placeholder");
    }

    fn sandbox_log_text(logs_dir: &Path) -> String {
        std::fs::read_dir(logs_dir)
            .expect("read log dir")
            .filter_map(|entry| std::fs::read_to_string(entry.ok()?.path()).ok())
            .collect()
    }

    #[test]
    fn rollback_skip_is_written_to_sandbox_log() {
        let tmp = TempDir::new().expect("tempdir");
        let logs = TempDir::new().expect("logs tempdir");
        let parent_handle = open_directory_no_reparse(
            tmp.path(),
            FILE_TRAVERSE | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            DirectoryOpenDisposition::OpenExisting,
        )
        .expect("open parent");
        let path = tmp.path().join("kept.txt");
        let handle = create_placeholder_file(&parent_handle, std::ffi::OsStr::new("kept.txt"))
            .expect("create placeholder");
        let mut guard = PlaceholderRollbackGuard::new(Some(logs.path()));
        guard.push(path.clone(), handle);
        std::fs::write(&path, "user data").expect("write user data");

        drop(guard);

        assert!(path.exists(), "non-empty file is kept");
        let log = sandbox_log_text(logs.path());
        assert!(
            log.contains("placeholder rollback skipped") && log.contains("non-empty"),
            "log: {log}"
        );
    }

    #[test]
    fn materialize_placeholders_rejects_parent_and_ancestor_junctions() {
        let tmp = TempDir::new().expect("tempdir");
        let logs = TempDir::new().expect("logs tempdir");
        let cwd = tmp.path().join("work");
        let codex_home = tmp.path().join("codex-home");
        let real = tmp.path().join("real");
        let link = tmp.path().join("link");
        for dir in [&cwd, &codex_home, &real.join("sub")] {
            std::fs::create_dir_all(dir).expect("create dir");
        }
        let status = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&link)
            .arg(&real)
            .output()
            .expect("run mklink");
        assert!(status.status.success(), "mklink /J failed: {status:?}");

        let through_parent = link.join("escaped.txt");
        let through_ancestor = link.join("sub").join("escaped.txt");
        let profile = workspace_profile(
            NetworkSandboxPolicy::Restricted,
            &[absolute(&through_parent), absolute(&through_ancestor)],
            /*exclude_tmpdir_env_var*/ true,
            /*exclude_slash_tmp*/ true,
        );
        let permissions =
            ResolvedWindowsSandboxPermissions::try_from_permission_profile_for_workspace_roots(
                &profile,
                workspace_roots_for(&cwd).as_slice(),
            )
            .expect("managed permission profile");

        let guard = materialize_missing_write_target_placeholders(
            &permissions,
            &cwd,
            &HashMap::new(),
            &codex_home,
            &[],
            Some(logs.path()),
            Vec::new,
        );

        assert!(guard.is_empty(), "nothing may be created through a junction");
        assert!(!real.join("escaped.txt").exists());
        assert!(!real.join("sub").join("escaped.txt").exists());
        let log = sandbox_log_text(logs.path());
        assert_eq!(
            log.matches("placeholder parent open failed").count(),
            2,
            "log: {log}"
        );
    }
}
