use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

use codex_protocol::models::PermissionProfile;
use codex_protocol::permissions::FileSystemAccessMode;
use codex_protocol::permissions::FileSystemPath;
use codex_protocol::permissions::FileSystemSandboxEntry;
use codex_protocol::permissions::FileSystemSpecialPath;
use codex_protocol::models::ManagedFileSystemPermissions;
use codex_protocol::permissions::NetworkSandboxPolicy;
use codex_utils_absolute_path::AbsolutePathBuf;

use crate::run_windows_sandbox_capture;

fn setup_test_env(cwd: &PathBuf) -> HashMap<String, String> {
    let mut env = HashMap::from([
        ("TEMP".to_string(), cwd.display().to_string()),
        ("TMP".to_string(), cwd.display().to_string()),
    ]);
    for name in ["PATH", "SystemRoot", "COMSPEC", "USERPROFILE"] {
        if let Ok(value) = std::env::var(name) {
            env.insert(name.to_string(), value);
        }
    }
    env
}

#[test]
fn test_end_to_end_missing_write_grant_reproduction_issue_58433() {
    let tmp = TempDir::new().expect("tempdir");
    let cwd = tmp.path().join("workspace");
    let codex_home = tmp.path().join("codex-home");
    let desktop_dir = tmp.path().join("desktop");
    fs::create_dir_all(&cwd).expect("create cwd");
    fs::create_dir_all(&codex_home).expect("create codex home");
    fs::create_dir_all(&desktop_dir).expect("create desktop dir");

    let brief_docx = desktop_dir.join("brief.docx");
    let forbidden_file = desktop_dir.join("forbidden.txt");
    assert!(!brief_docx.exists());
    assert!(!forbidden_file.exists());

    let profile = PermissionProfile::Managed {
        file_system: ManagedFileSystemPermissions::Restricted {
            entries: vec![
                FileSystemSandboxEntry::new(
                    FileSystemPath::Special {
                        value: FileSystemSpecialPath::Root,
                    },
                    FileSystemAccessMode::Read,
                ),
                FileSystemSandboxEntry::new(
                    FileSystemPath::Path {
                        path: AbsolutePathBuf::from_absolute_path(&cwd).unwrap().into(),
                    },
                    FileSystemAccessMode::Write,
                ),
                FileSystemSandboxEntry::new(
                    FileSystemPath::Path {
                        path: AbsolutePathBuf::from_absolute_path(&brief_docx).unwrap().into(),
                    },
                    FileSystemAccessMode::Write,
                ),
            ],
            glob_scan_max_depth: None,
        },
        network: NetworkSandboxPolicy::Restricted,
    };

    let env = setup_test_env(&cwd);
    let workspace_roots = vec![AbsolutePathBuf::from_absolute_path(&cwd).unwrap()];

    // 1. Run in-place write to brief.docx (the core #58433 repro)
    let write_cmd = vec![
        "cmd.exe".to_string(),
        "/c".to_string(),
        format!("echo hello from sandbox > \"{}\"", brief_docx.display()),
    ];

    let result = run_windows_sandbox_capture(
        &profile,
        workspace_roots.as_slice(),
        &codex_home,
        write_cmd,
        &cwd,
        env.clone(),
        Some(30_000),
        None,
    )
    .expect("run sandboxed write");

    assert_eq!(result.exit_code, 0, "sandbox command must succeed: stderr={}", String::from_utf8_lossy(&result.stderr));
    assert!(brief_docx.exists(), "brief.docx must exist after approved sandboxed write");
    let content = fs::read_to_string(&brief_docx).expect("read brief.docx");
    assert!(content.contains("hello from sandbox"), "content must match: {content}");

    // 2. Attempt write to sibling forbidden.txt in the same desktop directory (must fail with access denied)
    let forbidden_cmd = vec![
        "cmd.exe".to_string(),
        "/c".to_string(),
        format!("echo evil > \"{}\"", forbidden_file.display()),
    ];

    let forbidden_result = run_windows_sandbox_capture(
        &profile,
        workspace_roots.as_slice(),
        &codex_home,
        forbidden_cmd,
        &cwd,
        env,
        Some(30_000),
        None,
    )
    .expect("run forbidden command");

    assert_ne!(forbidden_result.exit_code, 0, "unauthorized sibling write must fail");
    assert!(!forbidden_file.exists(), "forbidden.txt must NOT be created");
}

#[test]
fn test_write_pattern_compatibility_matrix() {
    let tmp = TempDir::new().expect("tempdir");
    let cwd = tmp.path().join("workspace");
    let codex_home = tmp.path().join("codex-home");
    let target_dir = tmp.path().join("target_dir");
    fs::create_dir_all(&cwd).expect("create cwd");
    fs::create_dir_all(&codex_home).expect("create codex home");
    fs::create_dir_all(&target_dir).expect("create target dir");

    let target_file = target_dir.join("matrix_target.txt");
    let source_file = cwd.join("source.txt");
    fs::write(&source_file, "source content").expect("write source");
    assert!(!target_file.exists());

    let profile = PermissionProfile::Managed {
        file_system: ManagedFileSystemPermissions::Restricted {
            entries: vec![
                FileSystemSandboxEntry::new(
                    FileSystemPath::Special {
                        value: FileSystemSpecialPath::Root,
                    },
                    FileSystemAccessMode::Read,
                ),
                FileSystemSandboxEntry::new(
                    FileSystemPath::Path {
                        path: AbsolutePathBuf::from_absolute_path(&cwd).unwrap().into(),
                    },
                    FileSystemAccessMode::Write,
                ),
                FileSystemSandboxEntry::new(
                    FileSystemPath::Path {
                        path: AbsolutePathBuf::from_absolute_path(&target_file).unwrap().into(),
                    },
                    FileSystemAccessMode::Write,
                ),
            ],
            glob_scan_max_depth: None,
        },
        network: NetworkSandboxPolicy::Restricted,
    };

    let env = setup_test_env(&cwd);
    let workspace_roots = vec![AbsolutePathBuf::from_absolute_path(&cwd).unwrap()];

    // Row 2: Copy-Item / overwrite onto target from readable source
    let copy_cmd = vec![
        "cmd.exe".to_string(),
        "/c".to_string(),
        format!("copy /Y \"{}\" \"{}\"", source_file.display(), target_file.display()),
    ];

    let result = run_windows_sandbox_capture(
        &profile,
        workspace_roots.as_slice(),
        &codex_home,
        copy_cmd,
        &cwd,
        env.clone(),
        Some(30_000),
        None,
    )
    .expect("run copy command");

    assert_eq!(result.exit_code, 0, "copy command must succeed");
    assert_eq!(fs::read_to_string(&target_file).unwrap().trim(), "source content");

    // Row 3: Atomic sibling temp file + rename in ungranted parent -> denied
    let rename_cmd = vec![
        "cmd.exe".to_string(),
        "/c".to_string(),
        format!("echo tmp > \"{}\" && move /Y \"{}\" \"{}\"",
            target_dir.join("sibling.tmp").display(),
            target_dir.join("sibling.tmp").display(),
            target_file.display()
        ),
    ];

    let rename_res = run_windows_sandbox_capture(
        &profile,
        workspace_roots.as_slice(),
        &codex_home,
        rename_cmd,
        &cwd,
        env.clone(),
        Some(30_000),
        None,
    )
    .expect("run rename command");
    assert_ne!(rename_res.exit_code, 0, "sibling creation in ungranted parent must fail");

    // Row 4: Delete + recreate in ungranted parent -> recreate fails
    let delete_recreate_cmd = vec![
        "cmd.exe".to_string(),
        "/c".to_string(),
        format!("del /F \"{}\" && echo recreated > \"{}\"",
            target_file.display(),
            target_file.display()
        ),
    ];

    let del_res = run_windows_sandbox_capture(
        &profile,
        workspace_roots.as_slice(),
        &codex_home,
        delete_recreate_cmd,
        &cwd,
        env,
        Some(30_000),
        None,
    )
    .expect("run delete recreate command");
    assert_ne!(del_res.exit_code, 0, "recreation after deletion must fail because parent lacks FILE_ADD_FILE");
}

#[test]
fn test_missing_directory_pinning_58118() {
    let tmp = TempDir::new().expect("tempdir");
    let cwd = tmp.path().join("workspace");
    let codex_home = tmp.path().join("codex-home");
    let missing_dir = tmp.path().join("new_agent_dir");
    fs::create_dir_all(&cwd).expect("create cwd");
    fs::create_dir_all(&codex_home).expect("create codex home");
    assert!(!missing_dir.exists());

    // Option 1 pins the behavior for missing directory roots without descendant entries:
    // a 0-byte file is created, so mkdir in the child fails with AlreadyExists
    let profile = PermissionProfile::Managed {
        file_system: ManagedFileSystemPermissions::Restricted {
            entries: vec![
                FileSystemSandboxEntry::new(
                    FileSystemPath::Special {
                        value: FileSystemSpecialPath::Root,
                    },
                    FileSystemAccessMode::Read,
                ),
                FileSystemSandboxEntry::new(
                    FileSystemPath::Path {
                        path: AbsolutePathBuf::from_absolute_path(&cwd).unwrap().into(),
                    },
                    FileSystemAccessMode::Write,
                ),
                FileSystemSandboxEntry::new(
                    FileSystemPath::Path {
                        path: AbsolutePathBuf::from_absolute_path(&missing_dir).unwrap().into(),
                    },
                    FileSystemAccessMode::Write,
                ),
            ],
            glob_scan_max_depth: None,
        },
        network: NetworkSandboxPolicy::Restricted,
    };

    let env = setup_test_env(&cwd);
    let workspace_roots = vec![AbsolutePathBuf::from_absolute_path(&cwd).unwrap()];

    let mkdir_cmd = vec![
        "cmd.exe".to_string(),
        "/c".to_string(),
        format!("mkdir \"{}\"", missing_dir.display()),
    ];

    let result = run_windows_sandbox_capture(
        &profile,
        workspace_roots.as_slice(),
        &codex_home,
        mkdir_cmd,
        &cwd,
        env,
        Some(30_000),
        None,
    )
    .expect("run mkdir command");

    // Under Option 1, missing_dir was materialized as a file, so mkdir fails with "already exists"
    let stderr = String::from_utf8_lossy(&result.stderr);
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(
        stderr.to_lowercase().contains("already exists") || stdout.to_lowercase().contains("already exists"),
        "Option 1 pinning: mkdir on unscoped missing directory grant fails with AlreadyExists: stderr={stderr}, stdout={stdout}"
    );
}
