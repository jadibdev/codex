use std::path::Path;
use std::path::PathBuf;

pub fn canonicalize_path(path: &Path) -> PathBuf {
    dunce::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

pub fn canonical_path_key(path: &Path) -> String {
    canonicalize_path(path)
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase()
}

/// Whether `path_key` names something strictly below `ancestor_key`, comparing
/// whole components (`c:/a/protected` does not contain `c:/a/protected-old`).
/// Both keys must come from [`canonical_path_key`].
pub fn path_key_strictly_contains(ancestor_key: &str, path_key: &str) -> bool {
    let ancestor = ancestor_key.trim_end_matches('/');
    path_key
        .strip_prefix(ancestor)
        .is_some_and(|rest| rest.len() > 1 && rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::canonical_path_key;
    use super::path_key_strictly_contains;
    use pretty_assertions::assert_eq;
    use std::path::Path;

    #[test]
    fn canonical_path_key_normalizes_case_and_separators() {
        let windows_style = Path::new(r"C:\Users\Dev\Repo");
        let slash_style = Path::new("c:/users/dev/repo");

        assert_eq!(
            canonical_path_key(windows_style),
            canonical_path_key(slash_style)
        );
    }

    #[test]
    fn path_key_strictly_contains_respects_component_boundaries() {
        let protected = canonical_path_key(Path::new(r"C:\Proj\Protected"));
        let child = canonical_path_key(Path::new(r"c:\proj\protected\evil.txt"));
        let sibling = canonical_path_key(Path::new(r"C:\Proj\Protected-Old\ok.txt"));
        let drive_child = canonical_path_key(Path::new(r"C:\file.txt"));

        assert!(path_key_strictly_contains(&protected, &child));
        assert!(!path_key_strictly_contains(&protected, &sibling));
        assert!(!path_key_strictly_contains(&protected, &protected));
        assert!(path_key_strictly_contains("c:/", &drive_child));
    }
}
