//! FreeBSD implementation: procctl(2) reaper, jail_set(2), nmount(2).
//! NOTE: written without access to a FreeBSD toolchain; not compile-tested.

use std::ffi::{CString, c_char, c_int, c_uint, c_void};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;

use stacked_errors::{Result, StackableErr, bail};

// sys/procctl.h. libc has the PROC_REAP_* commands but not the structs.
// Padding is deliberately generous: the kernel copies in/out only its own
// sizeof, extra room in our buffer is harmless.
#[repr(C)]
#[derive(Default)]
struct ReaperStatus {
	flags: u32,
	children: u32,
	descendants: u32,
	reaper: i32,
	pid: i32,
	pad: [u32; 15],
}

#[repr(C)]
#[derive(Default)]
struct ReaperKill {
	sig: c_int,
	flags: u32,
	subtree: i32,
	killed: u32,
	fpid: i32,
	pad: [u32; 15],
}

fn procctl(cmd: c_int, data: *mut c_void) -> io::Result<()> {
	let rc = unsafe {
		libc::procctl(libc::P_PID, super::getpid() as libc::id_t, cmd, data)
	};
	if rc < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

pub fn become_reaper() -> Result<()> {
	procctl(libc::PROC_REAP_ACQUIRE, std::ptr::null_mut()).stack()
}

/// All live descendants (children, grandchildren, ...) of this reaper.
pub fn reaper_descendants() -> Result<u32> {
	let mut st = ReaperStatus::default();
	procctl(libc::PROC_REAP_STATUS, &mut st as *mut _ as *mut c_void).stack()?;
	Ok(st.descendants)
}

/// Signal every descendant. Returns how many were signalled.
pub fn reaper_kill_all(sig: i32) -> Result<u32> {
	let mut k = ReaperKill { sig, ..Default::default() }; // flags 0 = all descendants
	match procctl(libc::PROC_REAP_KILL, &mut k as *mut _ as *mut c_void) {
		Ok(()) => Ok(k.killed),
		// partial failures still signal the rest; report only if nothing worked
		Err(e) if k.killed > 0 => {
			let _ = e;
			Ok(k.killed)
		}
		Err(e) => Err(e).stack(),
	}
}

pub fn set_title(title: &str) {
	let t = CString::new(title.replace('\0', "")).unwrap_or_default();
	unsafe { libc::setproctitle(c"%s".as_ptr(), t.as_ptr()) };
}

pub fn peer_uid<T: AsRawFd>(s: &T) -> Result<u32> {
	let (mut uid, mut gid): (libc::uid_t, libc::gid_t) = (0, 0);
	if unsafe { libc::getpeereid(s.as_raw_fd(), &mut uid, &mut gid) } < 0 {
		return Err(io::Error::last_os_error()).stack();
	}
	Ok(uid)
}

// ---------------------------------------------------------------- jail_set(2)

/// Pre-built `jail_set` parameter list (name/value iovec pairs). The buffers
/// are kept alive in `_bufs`; `attach` makes only the system call.
pub struct JailSpec {
	_bufs: Vec<Vec<u8>>,
	iov: Vec<libc::iovec>,
}

// raw pointers point into `_bufs`, which is never modified after construction
unsafe impl Send for JailSpec {}
unsafe impl Sync for JailSpec {}

impl JailSpec {
	pub fn new(path: &str, host: &str, ips: &[String]) -> Result<Self> {
		fn cstr(s: &str) -> Result<Vec<u8>> {
			let c = CString::new(s).stack()?;
			Ok(c.into_bytes_with_nul())
		}
		let mut v4: Vec<u8> = Vec::new();
		let mut v6: Vec<u8> = Vec::new();
		for ip in ips {
			if let Ok(a) = ip.parse::<Ipv4Addr>() {
				v4.extend_from_slice(&a.octets());
			} else if let Ok(a) = ip.parse::<Ipv6Addr>() {
				v6.extend_from_slice(&a.octets());
			} else {
				bail!("jail ip= '{ip}' is not an IPv4/IPv6 address");
			}
		}
		let mut params: Vec<(Vec<u8>, Vec<u8>)> = vec![
			(cstr("path")?, cstr(path)?),
			(cstr("host.hostname")?, cstr(host)?),
		];
		// giving addresses makes the jail restricted to them (ip4=new/ip6=new
		// is implied by jail_set(2) when *.addr is passed)
		if !v4.is_empty() {
			params.push((cstr("ip4.addr")?, v4));
		}
		if !v6.is_empty() {
			params.push((cstr("ip6.addr")?, v6));
		}
		let mut bufs = Vec::new();
		for (k, v) in params {
			bufs.push(k);
			bufs.push(v);
		}
		let iov = bufs
			.iter()
			.map(|b| libc::iovec { iov_base: b.as_ptr() as *mut c_void, iov_len: b.len() })
			.collect();
		Ok(Self { _bufs: bufs, iov })
	}

	/// Create a jail for the calling process and attach to it.
	pub fn attach(&self) -> io::Result<()> {
		let rc = unsafe {
			libc::jail_set(
				self.iov.as_ptr() as *mut libc::iovec,
				self.iov.len() as c_uint,
				libc::JAIL_CREATE | libc::JAIL_ATTACH,
			)
		};
		if rc < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
	}
}

// ---------------------------------------------------------------- devfs

fn is_devfs(path: &str) -> bool {
	let Ok(c) = CString::new(path) else { return false };
	let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
	if unsafe { libc::statfs(c.as_ptr(), &mut fs) } < 0 {
		return false;
	}
	let n = unsafe { std::ffi::CStr::from_ptr(fs.f_fstypename.as_ptr() as *const c_char) };
	n.to_bytes() == b"devfs"
}

pub fn devfs_mount(dir: &str) -> Result<()> {
	let path = format!("{dir}/dev");
	if is_devfs(&path) {
		return Ok(());
	}
	let mut bufs: Vec<Vec<u8>> = Vec::new();
	for s in ["fstype", "devfs", "fspath", path.as_str(), "errmsg", ""] {
		let mut b = s.as_bytes().to_vec();
		b.push(0);
		bufs.push(b);
	}
	// errmsg value is a writable buffer for the kernel's message
	bufs[5] = vec![0u8; 255];
	let mut iov: Vec<libc::iovec> = bufs
		.iter_mut()
		.map(|b| libc::iovec { iov_base: b.as_mut_ptr() as *mut c_void, iov_len: b.len() })
		.collect();
	let rc = unsafe {
		libc::nmount(
			iov.as_mut_ptr(),
			iov.len() as c_uint,
			libc::MNT_NOEXEC | libc::MNT_NOSUID,
		)
	};
	if rc < 0 {
		let e = io::Error::last_os_error();
		let msg = &bufs[5];
		let n = msg.iter().position(|&b| b == 0).unwrap_or(0);
		let kmsg = String::from_utf8_lossy(&msg[..n]).into_owned();
		bail!("cannot mount devfs on {path}: {e} {kmsg}");
	}
	Ok(())
}

pub fn devfs_unmount(dir: &str) -> Result<()> {
	let path = format!("{dir}/dev");
	if !is_devfs(&path) {
		return Ok(());
	}
	let c = CString::new(path.as_str()).stack()?;
	if unsafe { libc::unmount(c.as_ptr(), 0) } < 0 {
		let e = io::Error::last_os_error();
		bail!("cannot unmount devfs from {path}: {e}");
	}
	Ok(())
}
