//! Command line parsing. Same options and directives as the DragonFly `svc`:
//! `-dfhp:r:R:xst:u:g:G:l:c:mj:k:T:F:`; options are only recognised left of the
//! directive, everything after the directive is passed through untouched.

use clap::{ArgAction, Parser};
use crate::sys;
use stacked_errors::{Result, StackableErr, bail};

/// Maximum number of supplementary groups for `-G` (NGROUPS on FreeBSD).
pub const NGROUPS: usize = 1023;

/// Raw clap view of the command line.
#[derive(Parser, Debug)]
#[command(name = "rsvc", disable_help_flag = true, disable_version_flag = true)]
struct Raw {
	#[arg(short = 'd', action = ArgAction::Count)]
	debug: u8,
	#[arg(short = 'f', action = ArgAction::Count)]
	foreground: u8,
	#[arg(short = 'h', action = ArgAction::Count)]
	help: u8,
	#[arg(short = 'p', overrides_with = "piddir")]
	piddir: Option<String>,
	#[arg(short = 'r', overrides_with = "restart_some")]
	restart_some: Option<String>,
	#[arg(short = 'R', overrides_with = "restart_all")]
	restart_all: Option<String>,
	#[arg(short = 'x', action = ArgAction::Count)]
	exit_mode: u8,
	#[arg(short = 's', action = ArgAction::Count)]
	sync_mode: u8,
	#[arg(short = 't', overrides_with = "termkill")]
	termkill: Option<String>,
	#[arg(short = 'u', overrides_with = "user")]
	user: Option<String>,
	#[arg(short = 'g', overrides_with = "group")]
	group: Option<String>,
	#[arg(short = 'G', overrides_with = "groups")]
	groups: Option<String>,
	#[arg(short = 'l', overrides_with = "logfile")]
	logfile: Option<String>,
	#[arg(short = 'c', overrides_with = "rootdir")]
	rootdir: Option<String>,
	#[arg(short = 'm', action = ArgAction::Count)]
	mountdev: u8,
	#[arg(short = 'j', overrides_with = "jaildir")]
	jaildir: Option<String>,
	#[arg(short = 'k', overrides_with = "jailspec")]
	jailspec: Option<String>,
	#[arg(short = 'T', overrides_with = "proctitle")]
	proctitle: Option<String>,
	#[arg(short = 'F', overrides_with = "restart_fail")]
	restart_fail: Option<String>,
	/// directive [label [args...]]; everything after the directive is verbatim.
	#[arg()]
	rest: Vec<String>,
}

/// Which processes count as "the service" and what restarting means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Restart {
	/// Neither -r nor -R given.
	#[default]
	None,
	/// -r: the main process only.
	Some,
	/// -R: all processes under management.
	All,
}

#[derive(Debug, Clone, Default)]
pub struct UserSpec {
	pub name: String,
	pub uid: u32,
	pub gid: u32,
}

/// Fully resolved command (what `command_t` was in the C code).
#[derive(Debug, Clone, Default)]
pub struct Cmd {
	pub debug: bool,
	pub foreground: bool,
	pub help: bool,
	/// `-p dir`, `None` = default directory.
	pub piddir: Option<String>,
	pub restart: Restart,
	/// True when -r/-R was given on this command line.
	pub restart_given: bool,
	pub restart_timo: u64,
	pub exit_mode: bool,
	pub sync_mode: bool,
	/// `-t`; `None` = default.
	pub termkill_timo: Option<u64>,
	pub user: Option<UserSpec>,
	pub group: Option<(String, u32)>,
	pub groups: Vec<u32>,
	pub logfile: Option<String>,
	pub rootdir: Option<String>,
	pub mountdev: bool,
	pub jaildir: Option<String>,
	pub jail_clean: bool,
	pub jail_ips: Vec<String>,
	pub proctitle: Option<String>,
	/// `-F count:per`; count 0 = disabled.
	pub restart_count: u64,
	pub restart_per: u64,
	pub directive: String,
	/// `None` for `all` or when no label given.
	pub label: Option<String>,
	/// True when no label argument was given at all (`all` clears it).
	pub empty_label: bool,
	/// Arguments after the label.
	pub ext: Vec<String>,
}

/// `strtol(s, NULL, 0)` semantics: optional sign, `0x` hex, leading `0` octal,
/// otherwise decimal. Trailing garbage is rejected (the C code ignored it, but
/// silently accepting `-r 5s` as 5 hides mistakes).
pub fn parse_c_int(s: &str) -> Result<i64> {
	let t = s.trim();
	let (neg, t) = match t.strip_prefix('-') {
		Some(r) => (true, r),
		None => (false, t.strip_prefix('+').unwrap_or(t)),
	};
	let (radix, digits) = if let Some(r) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
		(16, r)
	} else if t.len() > 1 && t.starts_with('0') {
		(8, &t[1..])
	} else {
		(10, t)
	};
	let v = i64::from_str_radix(digits, radix)
		.stack_err_with(|| format!("bad number: {s:?}"))?;
	Ok(if neg { -v } else { v })
}

fn parse_uint(s: &str) -> Result<u64> {
	let v = parse_c_int(s).stack()?;
	if v < 0 {
		bail!("negative value not allowed: {s:?}");
	}
	Ok(v as u64)
}

fn find_user(s: &str) -> Result<UserSpec> {
	let u = if s.starts_with(|c: char| c.is_ascii_digit()) {
		sys::user_by_uid(parse_c_int(s).stack()? as u32).stack()?
	} else {
		sys::user_by_name(s).stack()?
	};
	match u {
		Some(u) => Ok(UserSpec { name: u.name, uid: u.uid, gid: u.gid }),
		None => bail!("Cannot find user {s}"),
	}
}

fn find_group(s: &str) -> Result<(String, u32)> {
	let g = if s.starts_with(|c: char| c.is_ascii_digit()) {
		sys::group_by_gid(parse_c_int(s).stack()? as u32).stack()?
	} else {
		sys::group_by_name(s).stack()?
	};
	match g {
		Some(g) => Ok((g.name, g.gid)),
		None => bail!("Cannot find group {s}"),
	}
}

fn parse_jailspec(cmd: &mut Cmd, spec: &str) -> Result<()> {
	for item in spec.split(',').filter(|s| !s.is_empty()) {
		if item == "clean" {
			cmd.jail_clean = true;
		} else if let Some(ip) = item.strip_prefix("ip=") {
			if ip.is_empty() {
				bail!("jail-spec 'ip=' needs an address");
			}
			cmd.jail_ips.push(ip.to_string());
		} else {
			bail!("jail-spec '{item}' not understood");
		}
	}
	Ok(())
}

/// Options taking an argument (the `:` entries of the getopt string).
const VALUED: &str = "prRtugGlcjkTF";

/// Index of the first non-option argument, getopt style: options end at the
/// first word not starting with `-` (or after `--`), so everything after the
/// directive stays untouched even when it looks like an option.
fn split_options(args: &[String]) -> usize {
	let mut i = 0;
	while i < args.len() {
		let a = &args[i];
		if a == "--" {
			return i + 1;
		}
		if !a.starts_with('-') || a == "-" {
			return i;
		}
		let chars: Vec<char> = a.chars().skip(1).collect();
		for (n, c) in chars.iter().enumerate() {
			if VALUED.contains(*c) {
				if n + 1 == chars.len() {
					i += 1; // value is the next word
				}
				break;
			}
		}
		i += 1;
	}
	args.len()
}

/// Parse `argv[1..]`. Fails with a user-presentable error.
pub fn parse<I, S>(args: I) -> Result<Cmd>
where
	I: IntoIterator<Item = S>,
	S: Into<String>,
{
	let args: Vec<String> = args.into_iter().map(Into::into).collect();
	let split = split_options(&args);
	let argv = std::iter::once("rsvc".to_string())
		.chain(args[..split].iter().cloned())
		.chain(std::iter::once("--".to_string()))
		.chain(args[split..].iter().cloned());
	let raw = Raw::try_parse_from(argv).map_err(|e| {
		// keep clap's message but drop the usage noise
		let msg = e.to_string();
		let first = msg.lines().next().unwrap_or("bad options").to_string();
		stacked_errors::Error::from_err(first)
	})?;

	let mut c = Cmd {
		debug: raw.debug > 0,
		foreground: raw.foreground > 0 || raw.debug > 0,
		help: raw.help > 0,
		piddir: raw.piddir,
		exit_mode: raw.exit_mode > 0,
		sync_mode: raw.sync_mode > 0,
		logfile: raw.logfile,
		rootdir: raw.rootdir,
		mountdev: raw.mountdev > 0,
		jaildir: raw.jaildir,
		proctitle: raw.proctitle,
		empty_label: true,
		..Cmd::default()
	};

	// -r / -R: whichever the user wrote is honoured, the other is ignored
	// (they are documented as exclusive).
	match (raw.restart_some, raw.restart_all) {
		(Some(_), Some(_)) => bail!("-r and -R are exclusive"),
		(Some(t), None) => {
			c.restart = Restart::Some;
			c.restart_given = true;
			c.restart_timo = parse_uint(&t).stack()?;
		}
		(None, Some(t)) => {
			c.restart = Restart::All;
			c.restart_given = true;
			c.restart_timo = parse_uint(&t).stack()?;
		}
		(None, None) => {}
	}
	if let Some(t) = raw.termkill {
		c.termkill_timo = Some(parse_uint(&t).stack()?);
	}
	if let Some(u) = raw.user {
		c.user = Some(find_user(&u).stack()?);
	}
	if let Some(g) = raw.group {
		c.group = Some(find_group(&g).stack()?);
	}
	if let Some(gs) = raw.groups {
		for g in gs.split(',').filter(|s| !s.is_empty()) {
			if c.groups.len() >= NGROUPS {
				bail!("Too many groups specified, max {NGROUPS}");
			}
			c.groups.push(find_group(g).stack()?.1);
		}
	}
	if let Some(s) = raw.jailspec {
		parse_jailspec(&mut c, &s).stack()?;
	}
	if let Some(f) = raw.restart_fail {
		let mut it = f.splitn(2, ':');
		c.restart_count = parse_uint(it.next().unwrap_or("")).stack_err_with(|| format!("bad restart specification: {f}"))?;
		c.restart_per = match it.next() {
			Some(p) => parse_uint(p).stack_err_with(|| format!("bad restart specification: {f}"))?,
			None => 60,
		};
	}

	let mut rest = raw.rest.into_iter();
	match rest.next() {
		Some(d) => c.directive = d,
		None => {
			if c.help {
				c.directive = "help".into();
				return Ok(c);
			}
			bail!("No directive specified");
		}
	}
	if let Some(l) = rest.next() {
		c.empty_label = false;
		if l != "all" {
			c.label = Some(l);
		}
		c.ext = rest.collect();
	}
	Ok(c)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn numbers() {
		assert_eq!(parse_c_int("10").unwrap(), 10);
		assert_eq!(parse_c_int("0x10").unwrap(), 16);
		assert_eq!(parse_c_int("010").unwrap(), 8);
		assert_eq!(parse_c_int("-3").unwrap(), -3);
		assert_eq!(parse_c_int("0").unwrap(), 0);
		assert!(parse_c_int("5s").is_err());
	}

	#[test]
	fn options_then_directive() {
		let c = parse(["-fx", "-r", "5", "-p", "/tmp/d", "init", "web", "sleep", "-5", "-x"]).unwrap();
		assert!(c.foreground && c.exit_mode);
		assert_eq!(c.restart, Restart::Some);
		assert_eq!(c.restart_timo, 5);
		assert_eq!(c.piddir.as_deref(), Some("/tmp/d"));
		assert_eq!(c.directive, "init");
		assert_eq!(c.label.as_deref(), Some("web"));
		assert_eq!(c.ext, ["sleep", "-5", "-x"]);
	}

	#[test]
	fn all_and_empty_label() {
		let c = parse(["status"]).unwrap();
		assert!(c.empty_label && c.label.is_none());
		let c = parse(["stop", "all"]).unwrap();
		assert!(!c.empty_label && c.label.is_none());
	}

	#[test]
	fn restart_fail() {
		let c = parse(["-F", "3", "init", "a", "x"]).unwrap();
		assert_eq!((c.restart_count, c.restart_per), (3, 60));
		let c = parse(["-F", "3:10", "init", "a", "x"]).unwrap();
		assert_eq!((c.restart_count, c.restart_per), (3, 10));
		assert!(parse(["-F", "x", "init", "a", "x"]).is_err());
	}

	#[test]
	fn debug_forces_foreground_and_repeats_ok() {
		let c = parse(["-d", "-d", "-f", "list"]).unwrap();
		assert!(c.debug && c.foreground);
	}

	#[test]
	fn errors() {
		assert!(parse(Vec::<String>::new()).is_err());
		assert!(parse(["-k", "bogus", "list"]).is_err());
		assert!(parse(["-r", "1", "-R", "1", "list"]).is_err());
		assert!(parse(["-Z", "list"]).is_err());
	}
}
