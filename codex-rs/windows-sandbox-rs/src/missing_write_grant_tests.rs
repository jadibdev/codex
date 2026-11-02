#![cfg(test)]

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use tempfile::TempDir;

use codex_protocol::models::ManagedFileSystemPermissions;
use codex_protocol::models::PermissionProfile;
use codex_protocol::permissions::FileSystemAccessMode;
use codex_protocol::permissions::FileSystemPath;
use codex_protocol::permissions::FileSystemSandboxEntry;
use codex_protocol::permissions::FileSystemSpecialPath;
use codex_protocol::permissions::NetworkSandboxPolicy;
use codex_utils_absolute_path::AbsolutePathBuf;

use crate::CaptureResult;
use crate::run_windows_sandbox_capture;

struct Fixture {
    _tmp: TempDir,
    root: PathBuf,
    cwd: PathBuf,
    codex_home: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path().to_path_buf();
        let cwd = root.join("workspace");
        let codex_home = root.join("codex-home");
        fs::create_dir_all(&cwd).expect("create cwd");
        fs::create_dir_all(&codex_home).expect("create codex home");
        Self {
            _tmp: tmp,
            root,
            cwd,
            codex_home,
        }
    }

    /// Workspace-write profile for `cwd` plus exact write grants for `targets`.
    fn profile_granting(&self, targets: &[&Path]) -> PermissionProfile {
        let mut entries = vec![
            FileSystemSandboxEntry::new(
                FileSystemPath::Special {
                    value: FileSystemSpecialPath::Root,
                },
                FileSystemAccessMode::Read,
            ),
            write_entry(&self.cwd),
        ];
        entries.extend(targets.iter().map(|target| write_entry(target)));
        PermissionProfile::Managed {
            file_system: ManagedFileSystemPermissions::Restricted {
                entries,
                glob_scan_max_depth: None,
            },
            network: NetworkSandboxPolicy::Restricted,
        }
    }

    /// Runs `body` as a .cmd script from the workspace. Paths are passed through
    /// environment variables so no argument needs cmd.exe-incompatible quoting.
    fn run_script(
        &self,
        profile: &PermissionProfile,
        name: &str,
        body: &str,
        vars: &[(&str, &Path)],
    ) -> CaptureResult {
        let script = self.cwd.join(format!("{name}.cmd"));
        fs::write(&script, format!("@echo off\r\n{body}")).expect("write script");

        let mut env = HashMap::from([
            ("TEMP".to_string(), self.cwd.display().to_string()),
            ("TMP".to_string(), self.cwd.display().to_string()),
        ]);
        for name in ["PATH", "SystemRoot", "COMSPEC", "USERPROFILE"] {
            if let Ok(value) = std::env::var(name) {
                env.insert(name.to_string(), value);
            }
        }
        for (key, path) in vars {
            env.insert((*key).to_string(), path.display().to_string());
        }

        let workspace_roots = vec![AbsolutePathBuf::from_absolute_path(&self.cwd).unwrap()];
        run_windows_sandbox_capture(
            profile,
            workspace_roots.as_slice(),
            &self.codex_home,
            vec![
                "cmd.exe".to_string(),
                "/d".to_string(),
                "/c".to_string(),
                script.display().to_string(),
            ],
            &self.cwd,
            env,
            Some(30_000),
            None,
        )
        .expect("run sandboxed script")
    }
}

fn write_entry(path: &Path) -> FileSystemSandboxEntry {
    FileSystemSandboxEntry::new(
        FileSystemPath::Path {
            path: AbsolutePathBuf::from_absolute_path(path).unwrap().into(),
        },
        FileSystemAccessMode::Write,
    )
}

fn output(result: &CaptureResult) -> String {
    format!(
        "exit={} stdout={} stderr={}",
        result.exit_code,
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    )
}

#[test]
fn test_end_to_end_missing_write_grant_reproduction_issue_58433() {
    let fx = Fixture::new();
    let desktop_dir = fx.root.join("desktop");
    fs::create_dir_all(&desktop_dir).expect("create desktop dir");
    let brief_docx = desktop_dir.join("brief.docx");
    let forbidden_file = desktop_dir.join("forbidden.txt");
    assert!(!brief_docx.exists());
    let profile = fx.profile_granting(&[&brief_docx]);

    // The core #58433 repro: in-place write to an approved file that did not exist.
    let result = fx.run_script(
        &profile,
        "write-brief",
        "echo hello from sandbox> \"%TARGET%\"\r\nif exist \"%TARGET%\" exit /b 0\r\nexit /b 1\r\n",
        &[("TARGET", &brief_docx)],
    );
    assert_eq!(
        result.exit_code,
        0,
        "approved write must succeed: {}",
        output(&result)
    );
    let content = fs::read_to_string(&brief_docx).expect("read brief.docx");
    assert!(content.contains("hello from sandbox"), "content: {content}");

    // A sibling in the same ungranted directory stays denied. A failed `>`
    // redirection does not set ERRORLEVEL, so report via `if exist`.
    let result = fx.run_script(
        &profile,
        "write-sibling",
        "echo evil> \"%TARGET%\"\r\nif exist \"%TARGET%\" exit /b 0\r\nexit /b 1\r\n",
        &[("TARGET", &forbidden_file)],
    );
    assert_ne!(
        result.exit_code,
        0,
        "sibling write must fail: {}",
        output(&result)
    );
    assert!(
        !forbidden_file.exists(),
        "forbidden.txt must not be created"
    );
}

#[test]
fn test_write_pattern_compatibility_matrix() {
    let fx = Fixture::new();
    let target_dir = fx.root.join("target_dir");
    fs::create_dir_all(&target_dir).expect("create target dir");
    let target_file = target_dir.join("matrix_target.txt");
    let sibling_tmp = target_dir.join("sibling.tmp");
    let source_file = fx.cwd.join("source.txt");
    fs::write(&source_file, "source content").expect("write source");
    let profile = fx.profile_granting(&[&target_file]);

    // Row 2: copy-overwrite onto the placeholder.
    let result = fx.run_script(
        &profile,
        "copy-overwrite",
        "copy /Y \"%SOURCE%\" \"%TARGET%\" >nul\r\nexit /b %ERRORLEVEL%\r\n",
        &[("SOURCE", &source_file), ("TARGET", &target_file)],
    );
    assert_eq!(
        result.exit_code,
        0,
        "copy-overwrite must succeed: {}",
        output(&result)
    );
    assert_eq!(
        fs::read_to_string(&target_file).unwrap().trim(),
        "source content"
    );

    // Row 3: temp-file + rename needs a sibling create in the ungranted parent.
    let result = fx.run_script(
        &profile,
        "sibling-create",
        "echo tmp> \"%SIBLING%\"\r\nif exist \"%SIBLING%\" exit /b 0\r\nexit /b 1\r\n",
        &[("SIBLING", &sibling_tmp)],
    );
    assert_ne!(
        result.exit_code,
        0,
        "sibling create must fail: {}",
        output(&result)
    );
    assert!(!sibling_tmp.exists(), "sibling.tmp must not be created");

    // Row 4, within one command: delete succeeds (DELETE is on the file ACE),
    // recreate fails (needs FILE_ADD_FILE on the ungranted parent).
    // Exit 2 = delete failed, 1 = recreate failed, 0 = recreate succeeded.
    let result = fx.run_script(
        &profile,
        "delete-recreate",
        concat!(
            "del /F /Q \"%TARGET%\"\r\n",
            "if exist \"%TARGET%\" exit /b 2\r\n",
            "echo recreated> \"%TARGET%\"\r\n",
            "if exist \"%TARGET%\" exit /b 0\r\n",
            "exit /b 1\r\n",
        ),
        &[("TARGET", &target_file)],
    );
    assert_eq!(
        result.exit_code,
        1,
        "delete ok, recreate denied: {}",
        output(&result)
    );
    assert!(!target_file.exists(), "target must not be recreated");
}

#[test]
fn test_missing_directory_pinning_58118() {
    // Pins a known, disclosed regression (Option B for openai/codex#58433):
    // a missing directory grant outside every writable root becomes a 0-byte
    // file because FileSystemSandboxEntry has no file/directory kind. Update
    // this test if maintainers choose approval scoping or a protocol kind.
    let fx = Fixture::new();
    let missing_dir = fx.root.join("new_agent_dir");
    assert!(!missing_dir.exists());
    let profile = fx.profile_granting(&[&missing_dir]);

    // Option 1 pins today's behavior for a missing directory grant outside any
    // writable root: it is materialized as a 0-byte file, so mkdir fails.
    let result = fx.run_script(
        &profile,
        "mkdir-grant",
        "mkdir \"%TARGET%\"\r\nexit /b %ERRORLEVEL%\r\n",
        &[("TARGET", &missing_dir)],
    );
    assert_ne!(result.exit_code, 0, "mkdir must fail: {}", output(&result));
    assert!(
        missing_dir.is_file(),
        "grant must be materialized as a file"
    );
    assert_eq!(fs::metadata(&missing_dir).unwrap().len(), 0);
}

#[test]
fn test_spawn_failure_rolls_back_placeholder() {
    let fx = Fixture::new();
    let outside = fx.root.join("outside");
    fs::create_dir_all(&outside).expect("create outside dir");
    let target = outside.join("never-written.txt");
    let profile = fx.profile_granting(&[&target]);

    let workspace_roots = vec![AbsolutePathBuf::from_absolute_path(&fx.cwd).unwrap()];
    let missing_program = fx.root.join("no-such-program.exe");
    let result = run_windows_sandbox_capture(
        &profile,
        workspace_roots.as_slice(),
        &fx.codex_home,
        vec![missing_program.display().to_string()],
        &fx.cwd,
        HashMap::new(),
        Some(30_000),
        None,
    );

    assert!(result.is_err(), "spawning a missing program must fail");
    assert!(
        !target.exists(),
        "placeholder must be rolled back when spawn fails"
    );
}

#[test]
fn test_exclusive_create_fails_against_placeholder() {
    // Write-pattern row 5: CREATE_NEW sees the placeholder and fails with
    // "already exists", while CREATE_ALWAYS (overwrite) succeeds.
    let fx = Fixture::new();
    let target_dir = fx.root.join("exclusive");
    fs::create_dir_all(&target_dir).expect("create target dir");
    let target = target_dir.join("new.txt");
    let profile = fx.profile_granting(&[&target]);

    // Exit 3 = IOException (already exists), 1 = any other failure.
    let open_with = |mode: &str| {
        format!(
            "powershell -NoProfile -NonInteractive -Command \"try {{ [System.IO.File]::Open($env:TARGET, '{mode}').Close(); exit 0 }} catch [System.IO.IOException] {{ exit 3 }}\"\r\nexit /b %ERRORLEVEL%\r\n"
        )
    };

    let result = fx.run_script(
        &profile,
        "create-new",
        &open_with("CreateNew"),
        &[("TARGET", &target)],
    );
    assert_eq!(
        result.exit_code,
        3,
        "CreateNew must see the placeholder: {}",
        output(&result)
    );

    let result = fx.run_script(
        &profile,
        "create-always",
        &open_with("Create"),
        &[("TARGET", &target)],
    );
    assert_eq!(
        result.exit_code,
        0,
        "Create (overwrite) must succeed: {}",
        output(&result)
    );
}
