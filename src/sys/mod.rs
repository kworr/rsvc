//! Thin libc layer. Everything OS specific lives here; the rest of the crate
//! never touches `libc` directly. FreeBSD is the target platform, the Linux
//! implementation exists so the daemon can be built and smoke-tested elsewhere.

use std::ffi::{CStr, CString, c_char, c_int};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use stacked_errors::{Result, StackableErr, bail};

#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(target_os = "freebsd")]
pub use freebsd::*;

#[cfg(not(target_os = "freebsd"))]
mod linux;
#[cfg(not(target_os = "freebsd"))]
pub use linux::*;

/// `sun_path` limit (FreeBSD: 104, Linux: 108); use the smaller one.
pub const SUN_PATH_MAX: usize = 104;

fn cvt(ret: c_int) -> io::Result<c_int> {
	if ret < 0 { Err(io::Error::last_os_error()) } else { Ok(ret) }
}

pub fn geteuid() -> u32 {
	unsafe { libc::geteuid() }
}

pub fn getpid() -> i32 {
	unsafe { libc::getpid() }
}

// ---------------------------------------------------------------- passwd/group

#[derive(Debug, Clone)]
pub struct PwEnt {
	pub name: String,
	pub uid: u32,
	pub gid: u32,
}

#[derive(Debug, Clone)]
pub struct GrEnt {
	pub name: String,
	pub gid: u32,
}

fn lookup<T>(
	mut call: impl FnMut(*mut c_char, usize) -> io::Result<Option<T>>,
) -> Result<Option<T>> {
	let mut size = 1024usize;
	loop {
		let mut buf = vec![0 as c_char; size];
		match call(buf.as_mut_ptr(), size) {
			Err(e) if e.raw_os_error() == Some(libc::ERANGE) && size < (1 << 20) => size *= 2,
			other => return other.stack(),
		}
	}
}

fn pw_result(pwd: &libc::passwd) -> PwEnt {
	PwEnt {
		name: unsafe { CStr::from_ptr(pwd.pw_name) }.to_string_lossy().into_owned(),
		uid: pwd.pw_uid,
		gid: pwd.pw_gid,
	}
}

fn gr_result(grp: &libc::group) -> GrEnt {
	GrEnt {
		name: unsafe { CStr::from_ptr(grp.gr_name) }.to_string_lossy().into_owned(),
		gid: grp.gr_gid,
	}
}

pub fn user_by_name(name: &str) -> Result<Option<PwEnt>> {
	let c = CString::new(name).stack()?;
	lookup(|buf, len| {
		let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
		let mut res: *mut libc::passwd = std::ptr::null_mut();
		let rc = unsafe { libc::getpwnam_r(c.as_ptr(), &mut pwd, buf, len, &mut res) };
		if rc != 0 {
			Err(io::Error::from_raw_os_error(rc))
		} else if res.is_null() {
			Ok(None)
		} else {
			Ok(Some(pw_result(&pwd)))
		}
	})
}

pub fn user_by_uid(uid: u32) -> Result<Option<PwEnt>> {
	lookup(|buf, len| {
		let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
		let mut res: *mut libc::passwd = std::ptr::null_mut();
		let rc = unsafe { libc::getpwuid_r(uid as libc::uid_t, &mut pwd, buf, len, &mut res) };
		if rc != 0 {
			Err(io::Error::from_raw_os_error(rc))
		} else if res.is_null() {
			Ok(None)
		} else {
			Ok(Some(pw_result(&pwd)))
		}
	})
}

pub fn group_by_name(name: &str) -> Result<Option<GrEnt>> {
	let c = CString::new(name).stack()?;
	lookup(|buf, len| {
		let mut grp: libc::group = unsafe { std::mem::zeroed() };
		let mut res: *mut libc::group = std::ptr::null_mut();
		let rc = unsafe { libc::getgrnam_r(c.as_ptr(), &mut grp, buf, len, &mut res) };
		if rc != 0 {
			Err(io::Error::from_raw_os_error(rc))
		} else if res.is_null() {
			Ok(None)
		} else {
			Ok(Some(gr_result(&grp)))
		}
	})
}

pub fn group_by_gid(gid: u32) -> Result<Option<GrEnt>> {
	lookup(|buf, len| {
		let mut grp: libc::group = unsafe { std::mem::zeroed() };
		let mut res: *mut libc::group = std::ptr::null_mut();
		let rc = unsafe { libc::getgrgid_r(gid as libc::gid_t, &mut grp, buf, len, &mut res) };
		if rc != 0 {
			Err(io::Error::from_raw_os_error(rc))
		} else if res.is_null() {
			Ok(None)
		} else {
			Ok(Some(gr_result(&grp)))
		}
	})
}

// ---------------------------------------------------------------- fds/process

/// Pipe with both ends close-on-exec: `(read, write)`.
pub fn pipe_cloexec() -> Result<(OwnedFd, OwnedFd)> {
	let mut fds = [0 as c_int; 2];
	cvt(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }).stack()?;
	Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Non-blocking exclusive `flock(2)`. `Ok(false)` if somebody else holds it.
pub fn try_lock_exclusive(f: &File) -> Result<bool> {
	let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
	if rc == 0 {
		return Ok(true);
	}
	let e = io::Error::last_os_error();
	if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
		Ok(false)
	} else {
		Err(e).stack()
	}
}

/// # Safety
/// Same as `fork(2)`: the caller must be single threaded or only call
/// async-signal-safe functions in the child before exec.
pub unsafe fn fork() -> Result<i32> {
	cvt(unsafe { libc::fork() }).stack()
}

pub fn setsid() -> Result<()> {
	cvt(unsafe { libc::setsid() }).stack()?;
	Ok(())
}

/// Point stdin (and stdout/stderr unless `keep_out`) at /dev/null.
pub fn redirect_stdio_null(keep_out: bool) -> Result<()> {
	let f = std::fs::OpenOptions::new().read(true).write(true).open("/dev/null").stack()?;
	let fd = f.as_raw_fd();
	let n = if keep_out { 1 } else { 3 };
	for t in 0..n {
		cvt(unsafe { libc::dup2(fd, t) }).stack()?;
	}
	Ok(())
}

/// Duplicate our stdout (used as log sink in foreground mode).
pub fn dup_stdout() -> Result<File> {
	let fd = cvt(unsafe { libc::fcntl(1, libc::F_DUPFD_CLOEXEC, 3) }).stack()?;
	Ok(unsafe { File::from_raw_fd(fd) })
}

/// Reap one child (any). `None` when nothing is ready or there are no children.
pub fn reap_one() -> Result<Option<(i32, i32)>> {
	loop {
		let mut st: c_int = 0;
		let r = unsafe { libc::waitpid(-1, &mut st, libc::WNOHANG) };
		if r > 0 {
			return Ok(Some((r as i32, st as i32)));
		}
		if r == 0 {
			return Ok(None);
		}
		let e = io::Error::last_os_error();
		match e.raw_os_error() {
			Some(libc::EINTR) => continue,
			Some(libc::ECHILD) => return Ok(None),
			_ => return Err(e).stack(),
		}
	}
}

pub fn describe_status(st: i32) -> String {
	if libc::WIFEXITED(st) {
		format!("exited with status {}", libc::WEXITSTATUS(st))
	} else if libc::WIFSIGNALED(st) {
		format!("killed by signal {}", libc::WTERMSIG(st))
	} else {
		format!("status {st:#x}")
	}
}

/// `kill(2)`; a vanished process is not an error.
pub fn kill(pid: i32, sig: i32) -> Result<()> {
	if unsafe { libc::kill(pid, sig) } < 0 {
		let e = io::Error::last_os_error();
		if e.raw_os_error() != Some(libc::ESRCH) {
			return Err(e).stack();
		}
	}
	Ok(())
}

pub fn sync() {
	unsafe { libc::sync() }
}

pub fn gethostname() -> Result<String> {
	let mut buf = vec![0u8; 256];
	cvt(unsafe { libc::gethostname(buf.as_mut_ptr() as *mut c_char, buf.len() - 1) }).stack()?;
	let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
	buf.truncate(n);
	Ok(String::from_utf8_lossy(&buf).into_owned())
}

pub fn raw_fd_of<T: AsRawFd>(t: &T) -> RawFd {
	t.as_raw_fd()
}

// ---------------------------------------------------------------- child setup

/// Everything done in the forked child between fork and exec. Built in the
/// parent so that `apply` only has to make system calls.
pub struct ChildSetup {
	jail: Option<JailSpec>,
	chroot: Option<CString>,
	uid: Option<u32>,
	gid: Option<u32>,
	groups: Option<Vec<libc::gid_t>>,
}

impl ChildSetup {
	pub fn new(
		jaildir: Option<&str>,
		jail_ips: &[String],
		rootdir: Option<&str>,
		uid: Option<u32>,
		gid: Option<u32>,
		groups: &[u32],
	) -> Result<Self> {
		let jail = match jaildir {
			Some(dir) => {
				let host = gethostname().stack()?;
				Some(JailSpec::new(dir, &host, jail_ips).stack()?)
			}
			None => None,
		};
		let chroot = match rootdir {
			Some(d) if jaildir.is_none() => Some(CString::new(d).stack()?),
			_ => None,
		};
		let groups = if groups.is_empty() {
			None
		} else {
			Some(groups.iter().map(|&g| g as libc::gid_t).collect())
		};
		Ok(Self { jail, chroot, uid, gid, groups })
	}

	/// Runs in the child after fork. Order: jail/chroot, chdir /, gid,
	/// groups, uid (uid last, it drops the privilege to do the others).
	pub fn apply(&self) -> io::Result<()> {
		if let Some(j) = &self.jail {
			j.attach()?;
		} else if let Some(c) = &self.chroot {
			cvt(unsafe { libc::chroot(c.as_ptr()) })?;
		}
		if self.jail.is_some() || self.chroot.is_some() {
			cvt(unsafe { libc::chdir(c"/".as_ptr()) })?;
		}
		if let Some(g) = self.gid {
			cvt(unsafe { libc::setgid(g as libc::gid_t) })?;
		}
		if let Some(gs) = &self.groups {
			cvt(unsafe { libc::setgroups(gs.len() as _, gs.as_ptr()) })?;
		}
		if let Some(u) = self.uid {
			cvt(unsafe { libc::setuid(u as libc::uid_t) })?;
		}
		Ok(())
	}
}

pub fn require_root(what: &str) -> Result<()> {
	if geteuid() != 0 {
		bail!("{what} requires root");
	}
	Ok(())
}
