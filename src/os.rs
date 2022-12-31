use rocket::log::error_;
use std::{fs::Metadata, path::Path};

pub fn has_dot_file(c: impl AsRef<Path>) -> bool {
    let mut c = c.as_ref();
    loop {
        if let Some(f) = c.file_name() {
            if let Some(f) = f.to_str() {
                if f.starts_with('.') {
                    break true;
                }
            } else {
                error_!("Non UTF-8 path encountered");
                break true;
            }
        }
        if let Some(parent) = c.parent() {
            c = parent;
        } else {
            break false;
        }
    }
}

/// Windows constants
#[allow(unused)]
const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x100;
#[allow(unused)]
const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
#[allow(unused)]
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;

#[cfg(windows)]
pub fn has_hidden_file(m: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    m.file_attributes() & FILE_ATTRIBUTE_HIDDEN != 0
}

#[cfg(not(windows))]
pub fn has_hidden_file(m: &Metadata) -> bool {
    false
}

/// Linux constants
#[allow(unused)]
const SETUID: u32 = 0o4000;
#[allow(unused)]
const SETGID: u32 = 0o2000;

#[cfg(unix)]
pub fn has_setuid(m: &Metadata) -> bool {
    use std::os::unix::prelude::MetadataExt;
    m.mode() & (SETUID | SETGID) != 0
}

#[cfg(not(unix))]
pub fn has_setuid(_c: &Metadata) -> bool {
    false
}

#[cfg(unix)]
pub fn allowed(c: &Metadata) -> bool {
    true
}

#[cfg(windows)]
pub fn allowed(c: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    c.file_attributes() & (FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY) != 0
}

#[cfg(not(any(unix, windows)))]
pub fn allowed(c: &Metadata) -> bool {
    true
}

pub fn is_writable(c: &Metadata) -> bool {
    !c.permissions().readonly()
}

#[cfg(all(test, unix))]
mod unix_tests {
    use std::{fs::metadata, process::Command};

    use super::*;
    pub type Res = std::io::Result<()>;

    pub fn cmd(s: &str) -> Res {
        let mut parts = s.split_whitespace();
        let mut cmd = Command::new(parts.next().unwrap());
        cmd.args(parts);
        assert!(cmd.spawn()?.wait()?.success());
        Ok(())
    }

    #[test]
    fn check_setuid() -> Res {
        cmd("touch /tmp/file_perms")?;
        assert_eq!(has_setuid(&metadata("/tmp/file_perms")?), false);
        cmd("chmod u+s /tmp/file_perms")?;
        assert_eq!(has_setuid(&metadata("/tmp/file_perms")?), true);
        cmd("chmod g+s /tmp/file_perms")?;
        assert_eq!(has_setuid(&metadata("/tmp/file_perms")?), true);
        cmd("chmod u-s /tmp/file_perms")?;
        assert_eq!(has_setuid(&metadata("/tmp/file_perms")?), true);
        cmd("chmod g-s /tmp/file_perms")?;
        assert_eq!(has_setuid(&metadata("/tmp/file_perms")?), false);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_for_dotfile() {
        assert_eq!(has_dot_file(".file/something"), true);
        assert_eq!(has_dot_file("file/.something"), true);
        assert_eq!(has_dot_file("file/something."), false);
        assert_eq!(has_dot_file("file/something"), false);
        assert_eq!(has_dot_file("file/something.txt"), false);
    }
}
