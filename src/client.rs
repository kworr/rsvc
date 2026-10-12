//! Front end: finds the matching service sockets, talks to every one of them
//! concurrently and prints the results in label order.

use std::io::Write;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use smol::future::or;
use smol::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use smol::net::unix::UnixStream;
use smol::{LocalExecutor, Timer};
use stacked_errors::{Result, StackableErr};

use crate::daemon::{help_text, is_readonly};
use crate::opts::Cmd;
use crate::paths;
use crate::proto::{self, Line};
use crate::sys;

const KNOWN: &[&str] = &[
	"init", "start", "stop", "stopall", "restart", "exit", "kill", "list", "status", "log", "logf", "tailf",
	"logfile", "help",
];

/// A service socket found by the scan.
#[derive(Debug, Clone)]
struct Target {
	label: String,
	dir: PathBuf,
	/// `system` / `user`, only when both places are scanned
	tag: Option<&'static str>,
}

/// Directories to scan: (dir, tag).
fn scan_dirs(cmd: &Cmd) -> Result<Vec<(PathBuf, Option<&'static str>)>> {
	if let Some(p) = &cmd.piddir {
		return Ok(vec![(PathBuf::from(p), None)]);
	}
	if sys::geteuid() == 0 {
		return Ok(vec![(PathBuf::from(paths::SYSTEM_DIR), None)]);
	}
	let local = paths::local_dir().stack()?;
	if is_readonly(&cmd.directive) {
		// non-root may look at system services but never touch them
		Ok(vec![(PathBuf::from(paths::SYSTEM_DIR), Some("system")), (local, Some("user"))])
	} else {
		Ok(vec![(local, None)])
	}
}

fn scan(cmd: &Cmd) -> Result<Vec<Target>> {
	let mut found = Vec::new();
	let explicit = cmd.piddir.is_some();
	for (dir, tag) in scan_dirs(cmd).stack()? {
		let rd = match std::fs::read_dir(&dir) {
			Ok(r) => r,
			Err(_) if !explicit => continue, // e.g. no local dir yet
			Err(e) => return Err(e).stack_err_with(|| format!("Unable to scan \"{}\"", dir.display())),
		};
		for e in rd.flatten() {
			let name = e.file_name();
			let Some(label) = name.to_str().and_then(paths::label_of_sock) else { continue };
			let want = match &cmd.label {
				None => true,
				Some(l) => label.starts_with(l.as_str()),
			};
			if want {
				found.push(Target { label: label.to_string(), dir: dir.clone(), tag });
			}
		}
	}
	found.sort_by(|a, b| (&a.label, &a.dir).cmp(&(&b.label, &b.dir)));
	Ok(found)
}

enum Outcome {
	NoConnect(String),
	Done { data: Vec<u8>, rc: i32 },
}

/// Talk to one service. `stream_to` = print as it arrives (follow modes).
async fn query(t: Target, request: Rc<String>, cmd: Rc<Cmd>, stream: bool) -> Outcome {
	let sock = paths::sock_path(&t.dir, &t.label);
	let conn = match UnixStream::connect(&sock).await {
		Ok(c) => c,
		Err(e) => return Outcome::NoConnect(e.to_string()),
	};
	let tag_lines = matches!(cmd.directive.as_str(), "list" | "status");
	let (rd, mut wr) = smol::io::split(conn);
	if wr.write_all(request.as_bytes()).await.is_err() || wr.write_all(b"\n").await.is_err() {
		return Outcome::NoConnect("write failed".into());
	}
	let _ = wr.flush().await;

	let mut rd = BufReader::new(rd);
	let mut data = Vec::new();
	let mut line = Vec::new();
	let stdout = std::io::stdout();
	loop {
		line.clear();
		match rd.read_until(b'\n', &mut line).await {
			Ok(0) | Err(_) => return Outcome::Done { data, rc: 1 }, // connection lost mid-way
			Ok(_) => {}
		}
		let had_nl = line.last() == Some(&b'\n');
		if had_nl {
			line.pop();
		}
		match proto::unstuff(&line) {
			Line::End => break,
			Line::Data(d) => {
				let mut out = d.into_owned();
				if tag_lines && let Some(tag) = t.tag {
					out.extend_from_slice(format!(" [{tag}]").as_bytes());
				}
				out.push(b'\n');
				if stream {
					let mut h = stdout.lock();
					if h.write_all(&out).and_then(|_| h.flush()).is_err() {
						return Outcome::Done { data, rc: 0 }; // reader went away (e.g. | head)
					}
				} else {
					data.extend_from_slice(&out);
				}
			}
		}
	}
	// trailer; an old daemon closes right after the dot
	line.clear();
	let rc = or(
		async {
			match rd.read_until(b'\n', &mut line).await {
				Ok(n) if n > 0 => proto::parse_rc(&String::from_utf8_lossy(&line)),
				_ => None,
			}
		},
		async {
			Timer::after(Duration::from_secs(2)).await;
			None
		},
	)
	.await
	.unwrap_or(0);
	Outcome::Done { data, rc }
}

fn remove_stale(t: &Target) {
	let _ = std::fs::remove_file(paths::sock_path(&t.dir, &t.label));
	let pid = paths::pid_path(&t.dir, &t.label);
	// never remove the pid file of a live demon
	if !crate::daemon::demon_alive(&pid) {
		let _ = std::fs::remove_file(pid);
	}
}

/// Run a directive against all matching services. Returns the exit code.
pub fn run(cmd: Cmd, args: &[String]) -> Result<i32> {
	let directive = cmd.directive.clone();
	let d = directive.as_str();
	if d == "help" {
		print!("{}", help_text());
		return Ok(0);
	}
	if !KNOWN.contains(&d) {
		println!("Unknown directive: {d}");
		return Ok(1);
	}
	if cmd.empty_label && !is_readonly(d) {
		println!("Directive requires a label or 'all': {d}");
		return Ok(1);
	}

	let targets = scan(&cmd).stack()?;
	if targets.is_empty() {
		match d {
			"list" => return Ok(0),
			"status" => {
				eprintln!("no matching service");
				return Ok(2);
			}
			_ => {
				eprintln!("no matching service");
				return Ok(1);
			}
		}
	}

	let stream = matches!(d, "logf" | "tailf");
	let request = Rc::new(proto::encode_args(args));
	let force_remove = matches!(d, "exit" | "kill");
	let cmd = Rc::new(cmd);
	let ex = LocalExecutor::new();

	let rc = smol::block_on(ex.run(async {
		let tasks: Vec<_> = targets
			.iter()
			.map(|t| ex.spawn(query(t.clone(), request.clone(), cmd.clone(), stream)))
			.collect();
		let mut rc = 0;
		for (t, task) in targets.iter().zip(tasks) {
			match task.await {
				Outcome::NoConnect(why) => {
					println!("Unable to connect to service {}: {why}", t.label);
					if force_remove {
						remove_stale(t);
					}
					rc = rc.max(if d == "status" { 2 } else { 1 });
				}
				Outcome::Done { data, rc: r } => {
					let mut o = std::io::stdout().lock();
					let _ = o.write_all(&data);
					let _ = o.flush();
					rc = rc.max(r);
				}
			}
		}
		rc
	}));
	Ok(rc)
}

