//! Linux implementation: just enough to build and smoke-test the daemon.
//! The "reaper" is a child subreaper; descendants are found by scanning /proc.

use std::io;
use std::os::fd::AsRawFd;

use stacked_errors::{Result, StackableErr, bail};

pub fn become_reaper() -> Result<()> {
	let rc = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
	if rc < 0 {
		return Err(io::Error::last_os_error()).stack();
	}
	Ok(())
}

/// Live (non-zombie) descendants of this process (the real thing on FreeBSD
/// is procctl(PROC_REAP_*); here the /proc tree is walked instead).
fn children() -> Vec<i32> {
	let me = super::getpid();
	let mut parent_of: Vec<(i32, i32)> = Vec::new(); // (pid, ppid) of non-zombies
	let Ok(rd) = std::fs::read_dir("/proc") else { return Vec::new() };
	for e in rd.flatten() {
		let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else {
			continue;
		};
		let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else { continue };
		let Some(rest) = stat.rfind(')').map(|i| &stat[i + 1..]) else { continue };
		let mut it = rest.split_whitespace();
		let (state, ppid) = (it.next(), it.next().and_then(|s| s.parse::<i32>().ok()));
		if let (Some(st), Some(pp)) = (state, ppid) && st != "Z" {
			parent_of.push((pid, pp));
		}
	}
	let mut found = Vec::new();
	let mut frontier = vec![me];
	while let Some(p) = frontier.pop() {
		for &(pid, pp) in &parent_of {
			if pp == p && !found.contains(&pid) {
				found.push(pid);
				frontier.push(pid);
			}
		}
	}
	found
}

pub fn reaper_descendants() -> Result<u32> {
	Ok(children().len() as u32)
}

pub fn reaper_kill_all(sig: i32) -> Result<u32> {
	let mut n = 0;
	for pid in children() {
		super::kill(pid, sig).stack()?;
		n += 1;
	}
	Ok(n)
}

pub fn set_title(title: &str) {
	let mut b: Vec<u8> = title.bytes().filter(|&c| c != 0).take(15).collect();
	b.push(0);
	unsafe { libc::prctl(libc::PR_SET_NAME, b.as_ptr() as libc::c_ulong, 0, 0, 0) };
}

pub fn peer_uid<T: AsRawFd>(s: &T) -> Result<u32> {
	let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
	let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
	let rc = unsafe {
		libc::getsockopt(
			s.as_raw_fd(),
			libc::SOL_SOCKET,
			libc::SO_PEERCRED,
			&mut cred as *mut _ as *mut libc::c_void,
			&mut len,
		)
	};
	if rc < 0 {
		return Err(io::Error::last_os_error()).stack();
	}
	Ok(cred.uid as u32)
}

pub fn devfs_mount(_dir: &str) -> Result<()> {
	bail!("-m (devfs) is only supported on FreeBSD");
}

pub fn devfs_unmount(_dir: &str) -> Result<()> {
	Ok(())
}

pub struct JailSpec;

impl JailSpec {
	pub fn new(_path: &str, _host: &str, _ips: &[String]) -> Result<Self> {
		bail!("-j (jail) is only supported on FreeBSD");
	}
	pub fn attach(&self) -> io::Result<()> {
		Err(io::Error::from_raw_os_error(libc::ENOSYS))
	}
}
