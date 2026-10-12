//! Where pid files and sockets live.

use std::path::{Path, PathBuf};

use stacked_errors::{Result, StackableErr, bail};

use crate::sys;

pub const SYSTEM_DIR: &str = "/var/run";

/// Default directory for the current user (root: /var/run).
pub fn default_dir() -> Result<PathBuf> {
	if sys::geteuid() == 0 {
		return Ok(PathBuf::from(SYSTEM_DIR));
	}
	local_dir()
}

/// `$XDG_STATE_HOME/rsvc` or `~/.local/state/rsvc`.
pub fn local_dir() -> Result<PathBuf> {
	if let Some(x) = std::env::var_os("XDG_STATE_HOME").filter(|v| !v.is_empty()) {
		let p = PathBuf::from(x);
		if p.is_absolute() {
			return Ok(p.join("rsvc"));
		}
	}
	match std::env::var_os("HOME").filter(|v| !v.is_empty()) {
		Some(h) => Ok(PathBuf::from(h).join(".local/state/rsvc")),
		None => bail!("HOME is not set, cannot locate the per-user rsvc directory"),
	}
}

/// Create the local directory (mode 0700) if needed.
pub fn ensure_local_dir(p: &Path) -> Result<()> {
	use std::os::unix::fs::DirBuilderExt;
	std::fs::DirBuilder::new().recursive(true).mode(0o700).create(p).stack_err_with(|| format!("cannot create {}", p.display()))
}

pub fn pid_path(dir: &Path, label: &str) -> PathBuf {
	dir.join(format!("service.{label}.pid"))
}

pub fn sock_path(dir: &Path, label: &str) -> PathBuf {
	dir.join(format!("service.{label}.sk"))
}

/// Label from a directory entry name `service.<label>.sk`.
pub fn label_of_sock(name: &str) -> Option<&str> {
	let l = name.strip_prefix("service.")?.strip_suffix(".sk")?;
	if l.is_empty() { None } else { Some(l) }
}

pub fn check_label(label: &str) -> Result<()> {
	if label.is_empty() || label.contains('/') || label.contains('\0') {
		bail!("invalid label {label:?}");
	}
	Ok(())
}

pub fn check_sock_len(p: &Path) -> Result<()> {
	use std::os::unix::ffi::OsStrExt;
	if p.as_os_str().as_bytes().len() >= sys::SUN_PATH_MAX {
		bail!("socket path too long ({} >= {}): {}", p.as_os_str().len(), sys::SUN_PATH_MAX, p.display());
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn labels() {
		assert_eq!(label_of_sock("service.web.sk"), Some("web"));
		assert_eq!(label_of_sock("service.a.b.sk"), Some("a.b"));
		assert_eq!(label_of_sock("service..sk"), None);
		assert_eq!(label_of_sock("service.web.pid"), None);
		assert!(check_label("a/b").is_err());
	}
}
