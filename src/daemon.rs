//! The service demon: `rsvc init <label> <cmd...>` ends up here.
//!
//! Single threaded and cooperative (smol `LocalExecutor`). The only shared
//! state is `Service`, handed around as `Rc`; a `RefCell` borrow is never held
//! across an `.await`. Everything that waits has a deadline, so a service that
//! dies in a strange way can no longer wedge a `stop` (the C code could).
//!
//! Fork/daemonize happens in [`init`] *before* any smol primitive is created:
//! async-io starts a helper thread lazily and forking afterwards would be
//! asking for trouble.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_signal::{Signal, Signals};
use smol::future::or;
use smol::io::{AsyncReadExt, AsyncWriteExt};
use smol::stream::StreamExt;
use smol::{Async, LocalExecutor, Timer};
use stacked_errors::{Result, StackableErr, bail};

use crate::log::Log;
use crate::opts::{Cmd, Restart};
use crate::paths;
use crate::proto::{self, Escaper};
use crate::sys;

const DEFAULT_TERMKILL: u64 = 10;
/// Extra time (beyond -t) a `stop` waits for the service to really be gone.
const STOP_GRACE: u64 = 30;
const EXIT_GRACE: Duration = Duration::from_millis(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
	Term,
	Kill,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Run {
	Stopped,
	Started,
	/// phase and the time of the last signal sent
	Stopping(Phase, Instant),
}

struct State {
	run: Run,
	direct: Option<i32>,
	last_stop: Instant,
	manual_stop: bool,
	exit_mode: bool,
	exit_at: Option<Instant>,
	restart: Restart,
	restart_timo: u64,
	termkill: u64,
	/// -F tripped: no automatic restarts until a manual `start`
	failed: bool,
	auto_starts: VecDeque<Instant>,
	logfile: Option<String>,
}

pub struct Service {
	label: String,
	init: Cmd,
	st: RefCell<State>,
	log: RefCell<Log>,
	changed: event_listener::Event,
	owner_uid: u32,
	shutdown: Cell<bool>,
	ex: Rc<LocalExecutor<'static>>,
}

/// Directives that only read; everybody who can reach the socket may use them.
pub fn is_readonly(directive: &str) -> bool {
	matches!(directive, "status" | "list" | "log" | "logf" | "tailf" | "help")
}

/// Directives answered by streaming from the log ring.
fn is_log(directive: &str) -> bool {
	matches!(directive, "log" | "logf" | "tailf")
}

pub fn help_text() -> &'static str {
	"rsvc [options] directive [label [additional_args]]\n\
	 \n\
	 Directives: init start stop stopall restart exit\n\
	 \x20		   kill list status log logf tailf logfile\n\
	 \x20		   help\n"
}

fn open_logfile(path: &str) -> Result<File> {
	OpenOptions::new()
		.create(true)
		.append(true)
		.mode(0o640)
		.open(path)
		.stack_err_with(|| format!("unable to open/create \"{path}\""))
}

impl Service {
	fn new(init: Cmd, ex: Rc<LocalExecutor<'static>>) -> Rc<Self> {
		let label = init.label.clone().unwrap_or_default();
		let mut restart = init.restart;
		if init.exit_mode && restart == Restart::None {
			restart = Restart::Some; // documented: -x implies -r
		}
		let st = State {
			run: Run::Stopped,
			direct: None,
			last_stop: Instant::now(),
			manual_stop: false,
			exit_mode: init.exit_mode,
			exit_at: None,
			restart,
			restart_timo: init.restart_timo,
			termkill: init.termkill_timo.unwrap_or(DEFAULT_TERMKILL),
			failed: false,
			auto_starts: VecDeque::new(),
			logfile: init.logfile.clone(),
		};
		Rc::new(Self {
			label,
			init,
			st: RefCell::new(st),
			log: RefCell::new(Log::new()),
			changed: event_listener::Event::new(),
			owner_uid: sys::geteuid(),
			shutdown: Cell::new(false),
			ex,
		})
	}

	// ------------------------------------------------------------ messages

	/// Daemon message into the log ring (and logfile).
	fn note(&self, msg: &str) {
		let line = format!("svc {}: {}\n", self.label, msg);
		self.log.borrow_mut().push(line.as_bytes());
	}

	/// Message that is both logged and answered to the commanding client.
	fn say(&self, out: &mut Vec<u8>, msg: &str) {
		self.note(msg);
		out.extend_from_slice(format!("svc {}: {}\n", self.label, msg).as_bytes());
	}

	fn debug(&self, msg: &str) {
		if self.init.debug {
			self.note(msg);
		}
	}

	// ------------------------------------------------------------ state machine

	fn alive(s: &State) -> bool {
		if s.restart == Restart::Some {
			s.direct.is_some()
		} else {
			s.direct.is_some() || sys::reaper_descendants().unwrap_or(0) > 0
		}
	}

	fn mark_stopped(&self, s: &mut State, now: Instant) {
		if s.run != Run::Stopped {
			s.run = Run::Stopped;
			s.last_stop = now;
			if self.init.sync_mode {
				sys::sync();
			}
			self.changed.notify(usize::MAX);
		}
	}

	fn signal(&self, s: &State, sig: i32) {
		if let Some(p) = s.direct && let Err(e) = sys::kill(p, sig) {
			self.note(&format!("kill {p}: {e}"));
		}
		if s.restart != Restart::Some && let Err(e) = sys::reaper_kill_all(sig) {
			self.note(&format!("signalling descendants: {e}"));
		}
	}

	fn begin_stop(&self, s: &mut State, now: Instant) {
		if s.termkill == 0 {
			s.run = Run::Stopping(Phase::Kill, now);
			self.note("sigkill");
			self.signal(s, libc::SIGKILL);
		} else {
			s.run = Run::Stopping(Phase::Term, now);
			self.note("sigterm");
			self.signal(s, libc::SIGTERM);
		}
		s.last_stop = now;
		self.changed.notify(usize::MAX);
	}

	fn reap(&self) {
		loop {
			match sys::reap_one() {
				Ok(Some((pid, status))) => {
					let mut s = self.st.borrow_mut();
					if s.direct == Some(pid) {
						s.direct = None;
						drop(s);
						self.note(&format!("lost direct child {pid} ({})", sys::describe_status(status)));
					} else {
						drop(s);
						self.debug(&format!("reap indirect child {pid}"));
					}
				}
				Ok(None) => break,
				Err(e) => {
					self.note(&format!("waitpid: {e}"));
					break;
				}
			}
		}
	}

	/// One supervisor step. Cheap and idempotent; called on every event and
	/// at least once a second.
	fn tick(self: &Rc<Self>) {
		self.reap();
		let now = Instant::now();
		let mut s = self.st.borrow_mut();
		match s.run {
			Run::Started => {
				let direct_lost = s.direct.is_none();
				if s.exit_mode && direct_lost && s.restart == Restart::Some {
					s.restart = Restart::All; // -x: nothing may be left behind
				}
				if !Self::alive(&s) {
					self.mark_stopped(&mut s, now);
				} else if s.exit_mode && direct_lost {
					self.begin_stop(&mut s, now);
				}
			}
			Run::Stopping(phase, since) => {
				if !Self::alive(&s) {
					self.mark_stopped(&mut s, now);
				} else {
					let waited = now.duration_since(since);
					match phase {
						Phase::Term if waited >= Duration::from_secs(s.termkill) => {
							s.run = Run::Stopping(Phase::Kill, now);
							self.note("sigkill");
							self.signal(&s, libc::SIGKILL);
						}
						Phase::Kill if waited >= Duration::from_secs(1) => {
							s.run = Run::Stopping(Phase::Kill, now);
							self.signal(&s, libc::SIGKILL);
						}
						_ => {}
					}
				}
			}
			Run::Stopped => {
				if s.exit_mode {
					match s.exit_at {
						None => {
							s.exit_at = Some(now + EXIT_GRACE);
							self.note("service demon exiting");
						}
						Some(t) if now >= t => {
							self.shutdown.set(true);
							self.changed.notify(usize::MAX);
						}
						Some(_) => {}
					}
				} else if s.manual_stop || s.failed || s.restart == Restart::None {
					// wait for a commanded action
				} else if now.duration_since(s.last_stop) >= Duration::from_secs(s.restart_timo.max(1)) {
					if self.init.restart_count > 0 {
						let per = Duration::from_secs(self.init.restart_per);
						while s.auto_starts.front().is_some_and(|t| now.duration_since(*t) > per) {
							s.auto_starts.pop_front();
						}
						if s.auto_starts.len() as u64 >= self.init.restart_count {
							s.failed = true;
							drop(s);
							self.note(&format!(
								"FAILED: restarted {} times within {}s, giving up (manual start required)",
								self.init.restart_count, self.init.restart_per
							));
							return;
						}
					}
					s.auto_starts.push_back(now);
					drop(s);
					match self.spawn() {
						Ok(pid) => self.note(&format!("Starting pid {pid}")),
						Err(e) => self.note(&format!("start failed: {e}")),
					}
				}
			}
		}
	}

	/// Start the service process. Moves to `Started` or back to `Stopped`.
	fn spawn(self: &Rc<Self>) -> Result<i32> {
		let init = &self.init;
		let result = (|| -> Result<i32> {
			let (rd, wr) = sys::pipe_cloexec().stack()?;
			let uid = init.user.as_ref().map(|u| u.uid);
			// -g beats the user's gid; -G (groups) replaces the gid logic entirely
			let gid = if let Some(g) = &init.group {
				Some(g.1)
			} else if init.groups.is_empty() {
				init.user.as_ref().map(|u| u.gid)
			} else {
				None
			};
			let setup = Arc::new(
				sys::ChildSetup::new(
					init.jaildir.as_deref(),
					&init.jail_ips,
					init.rootdir.as_deref(),
					uid,
					gid,
					&init.groups,
				)
				.stack()?,
			);

			let mut c = Command::new(&init.ext[0]);
			c.args(&init.ext[1..])
				.stdin(Stdio::null())
				.stdout(Stdio::from(wr.try_clone().stack()?))
				.stderr(Stdio::from(wr));
			if init.jail_clean {
				c.env_clear();
			}
			// SAFETY: `apply` only makes system calls (no allocation).
			unsafe {
				c.pre_exec(move || setup.apply());
			}
			let child = c.spawn().stack_err_with(|| format!("cannot execute {:?}", init.ext[0]))?;
			drop(c); // closes our copies of the write end
			let pid = child.id() as i32;
			drop(child); // not waited for here: the supervisor reaps with waitpid(-1)

			let reader = Async::new(File::from(rd)).stack()?;
			let me = self.clone();
			self.ex.spawn(async move { me.pump(reader).await }).detach();
			Ok(pid)
		})();

		let now = Instant::now();
		let mut s = self.st.borrow_mut();
		match result {
			Ok(pid) => {
				s.run = Run::Started;
				s.direct = Some(pid);
				s.manual_stop = false;
				s.exit_at = None;
				self.changed.notify(usize::MAX);
				Ok(pid)
			}
			Err(e) => {
				s.direct = None;
				self.mark_stopped(&mut s, now);
				s.last_stop = now;
				Err(e)
			}
		}
	}

	/// Copy service output into the log until every writer is gone.
	async fn pump(self: Rc<Self>, mut rd: Async<File>) {
		let mut buf = [0u8; 4096];
		loop {
			match rd.read(&mut buf).await {
				Ok(0) | Err(_) => break,
				Ok(n) => self.log.borrow_mut().push(&buf[..n]),
			}
		}
	}

	async fn wait_stopped(&self, deadline: Instant) -> bool {
		loop {
			if self.st.borrow().run == Run::Stopped {
				return true;
			}
			if Instant::now() >= deadline {
				return false;
			}
			let l = self.changed.listen();
			or(
				async { l.await; },
				async { Timer::at(deadline).await; },
			).await;
		}
	}

	// ------------------------------------------------------------ directives

	async fn do_start(self: &Rc<Self>, out: &mut Vec<u8>) -> i32 {
		let deadline = Instant::now() + Duration::from_secs(self.st.borrow().termkill + STOP_GRACE);
		if matches!(self.st.borrow().run, Run::Stopping(..)) {
			self.say(out, "Waiting for previous action to complete");
		}
		// Started means done; only a Stopping service needs waiting for.
		loop {
			let r = self.st.borrow().run;
			match r {
				Run::Started => {
					let pid = self.st.borrow().direct;
					self.say(out, &format!("Already started pid {}", pid.unwrap_or(-1)));
					return 0;
				}
				Run::Stopped => break,
				Run::Stopping(..) => {
					if !self.wait_stopped(deadline).await {
						self.say(out, "Giving up waiting for action");
						return 1;
					}
				}
			}
		}
		{
			let mut s = self.st.borrow_mut();
			s.manual_stop = false;
			s.failed = false;
			s.auto_starts.clear();
		}
		match self.spawn() {
			Ok(pid) => {
				self.say(out, &format!("Starting pid {pid}"));
				0
			}
			Err(e) => {
				self.say(out, &format!("start failed: {e}"));
				1
			}
		}
	}

	/// Stop the service. `permanent` keeps the overrides (exit/kill); stop
	/// and restart only override temporarily, like the original.
	async fn do_stop(self: &Rc<Self>, cmd: &Cmd, mode: StopMode, out: &mut Vec<u8>) -> i32 {
		let saved;
		{
			let mut s = self.st.borrow_mut();
			saved = (s.restart, s.restart_timo, s.termkill);
			match mode {
				StopMode::StopAll => s.restart = Restart::All,
				StopMode::Exit | StopMode::Kill => {
					s.restart = Restart::All;
					s.exit_mode = true;
				}
				StopMode::Stop => {
					if cmd.restart_given {
						s.restart = cmd.restart;
						s.restart_timo = cmd.restart_timo;
					}
				}
			}
			if mode == StopMode::Kill {
				s.termkill = 0;
			} else if let Some(t) = cmd.termkill_timo {
				s.termkill = t;
			}
			s.manual_stop = true;
		}
		let verb = match mode {
			StopMode::Exit | StopMode::Kill => "Stopping and Exiting",
			_ => "Stopping",
		};
		if !matches!(mode, StopMode::Exit | StopMode::Kill) && {
			let s = self.st.borrow();
			s.run == Run::Stopped && !Self::alive(&s)
		} {
			self.say(out, "Already stopped");
		} else {
			self.say(out, verb);
		}

		let now = Instant::now();
		let deadline;
		{
			let mut s = self.st.borrow_mut();
			deadline = now + Duration::from_secs(s.termkill + STOP_GRACE);
			match s.run {
				Run::Started => self.begin_stop(&mut s, now),
				// stopall/exit/kill: also sweep up stragglers of a service that is already "stopped"
				Run::Stopped if Self::alive(&s) => self.begin_stop(&mut s, now),
				Run::Stopping(..) => {
					// TERM already out; a tighter -t / kill must not wait for the old timer
					if s.termkill == 0 {
						s.run = Run::Stopping(Phase::Kill, now);
						self.signal(&s, libc::SIGKILL);
					}
					self.changed.notify(usize::MAX);
				}
				Run::Stopped => {}
			}
		}
		let ok = self.wait_stopped(deadline).await;
		if !ok {
			self.say(out, "Giving up waiting for stop");
		}
		if !matches!(mode, StopMode::Exit | StopMode::Kill) {
			let mut s = self.st.borrow_mut();
			s.restart = saved.0;
			s.restart_timo = saved.1;
			s.termkill = saved.2;
		}
		if ok { 0 } else { 1 }
	}

	async fn do_restart(self: &Rc<Self>, cmd: &Cmd, out: &mut Vec<u8>) -> i32 {
		let rc = self.do_stop(cmd, StopMode::Stop, out).await;
		if rc != 0 {
			return rc;
		}
		let timo = if cmd.restart_given { cmd.restart_timo } else { self.st.borrow().restart_timo };
		if timo > 0 {
			Timer::after(Duration::from_secs(timo)).await;
		}
		self.do_start(out).await
	}

	fn status_word(&self) -> &'static str {
		let s = self.st.borrow();
		match s.run {
			Run::Started => "running",
			Run::Stopping(..) => "killing",
			Run::Stopped if s.exit_mode => "stopped (exiting)",
			Run::Stopped if s.manual_stop => "stopped (manual)",
			Run::Stopped if s.failed => "stopped (failed)",
			Run::Stopped => "stopped",
		}
	}

	fn do_logfile(&self, cmd: &Cmd, out: &mut Vec<u8>) -> i32 {
		let cur = self.st.borrow().logfile.clone();
		let Some(path) = cmd.ext.first().cloned().or(cur.clone()) else {
			return 0;
		};
		if cur.as_deref() == Some(path.as_str()) {
			self.say(out, &format!("Reopen logfile {path}"));
		} else {
			self.say(out, &format!("Change logfile to {path}"));
		}
		let sink = if path == "/dev/null" {
			None
		} else {
			match open_logfile(&path) {
				Ok(f) => Some(f),
				Err(e) => {
					self.say(out, &format!("{e}"));
					return 1;
				}
			}
		};
		self.log.borrow_mut().set_sink(sink);
		self.st.borrow_mut().logfile = Some(path);
		0
	}

	/// Execute a non-streaming directive; returns the exit code.
	pub async fn directive(self: &Rc<Self>, cmd: &Cmd, out: &mut Vec<u8>) -> i32 {
		match cmd.directive.as_str() {
			"start" => self.do_start(out).await,
			"stop" => self.do_stop(cmd, StopMode::Stop, out).await,
			"stopall" => self.do_stop(cmd, StopMode::StopAll, out).await,
			"restart" => self.do_restart(cmd, out).await,
			"exit" => self.do_stop(cmd, StopMode::Exit, out).await,
			"kill" => self.do_stop(cmd, StopMode::Kill, out).await,
			"list" => {
				out.extend_from_slice(format!("{:<16}\n", self.label).as_bytes());
				0
			}
			"status" => {
				let w = self.status_word();
				out.extend_from_slice(format!("{:<16} {}\n", self.label, w).as_bytes());
				if w == "running" { 0 } else { 1 }
			}
			"logfile" => self.do_logfile(cmd, out),
			"help" => {
				out.extend_from_slice(help_text().as_bytes());
				0
			}
			other => {
				out.extend_from_slice(format!("Unknown directive: {other}\n").as_bytes());
				1
			}
		}
	}

	// ------------------------------------------------------------ connections

	async fn handle(self: Rc<Self>, stream: Async<std::os::unix::net::UnixStream>) {
		let peer = sys::peer_uid(stream.get_ref()).ok();
		let (mut rd, mut wr) = smol::io::split(stream);

		let line = match read_request(&mut rd).await {
			Some(l) => l,
			None => return,
		};
		let text = String::from_utf8_lossy(&line).into_owned();
		let mut out = Vec::new();
		let mut esc = Escaper::default();
		let rc;

		match crate::opts::parse(proto::decode_args(&text)) {
			Err(e) => {
				out.extend_from_slice(format!("{e}\n").as_bytes());
				rc = 1;
			}
			Ok(cmd) => {
				let allowed = is_readonly(&cmd.directive)
					|| matches!(peer, Some(u) if u == 0 || u == self.owner_uid);
				if !allowed {
					out.extend_from_slice(
						format!("svc {}: permission denied for directive {}\n", self.label, cmd.directive).as_bytes(),
					);
					rc = 1;
				} else if is_log(&cmd.directive) {
					self.stream_log(&cmd, &mut rd, &mut wr).await;
					return;
				} else {
					rc = self.directive(&cmd, &mut out).await;
				}
			}
		}
		let mut wire = Vec::new();
		esc.push(&out, &mut wire);
		esc.finish(&mut wire);
		wire.extend_from_slice(proto::END);
		wire.extend_from_slice(format!("rc {rc}\n").as_bytes());
		let _ = wr.write_all(&wire).await;
		let _ = wr.flush().await;
	}

	/// `log`, `logf`, `tailf`.
	async fn stream_log<R, W>(&self, cmd: &Cmd, rd: &mut R, wr: &mut W)
	where
		R: smol::io::AsyncRead + Unpin,
		W: smol::io::AsyncWrite + Unpin,
	{
		let follow = cmd.directive != "log";
		let mut pos = {
			let l = self.log.borrow();
			if cmd.directive == "tailf" { l.end() } else { l.start() }
		};
		let mut esc = Escaper::default();
		loop {
			let (chunk, listener) = {
				let l = self.log.borrow();
				let listener = l.event.listen();
				(l.read_from(pos), listener)
			};
			let mut wire = Vec::new();
			if chunk.lost {
				esc.push(b"\n(LOG DATA LOST)\n", &mut wire);
			}
			esc.push(&chunk.data, &mut wire);
			pos = chunk.next;
			if !follow {
				esc.finish(&mut wire);
				wire.extend_from_slice(proto::END);
				wire.extend_from_slice(b"rc 0\n");
			}
			if !wire.is_empty() && wr.write_all(&wire).await.is_err() {
				return;
			}
			let _ = wr.flush().await;
			if !follow {
				return;
			}
			// wake on new data or when the client goes away
			let gone = async {
				let mut b = [0u8; 64];
				loop {
					match rd.read(&mut b).await {
						Ok(0) | Err(_) => return true,
						Ok(_) => {}
					}
				}
			};
			let woke = or(async { listener.await; false }, gone).await;
			if woke {
				return;
			}
		}
	}
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StopMode {
	Stop,
	StopAll,
	Exit,
	Kill,
}

/// Read one request line: ends at a newline that is not backslash-escaped.
async fn read_request<R: smol::io::AsyncRead + Unpin>(rd: &mut R) -> Option<Vec<u8>> {
	let mut line = Vec::new();
	let mut esc = false;
	let mut buf = [0u8; 1024];
	let deadline = Instant::now() + Duration::from_secs(10);
	loop {
		let n = or(async { rd.read(&mut buf).await.ok() }, async {
			Timer::at(deadline).await;
			None
		})
		.await?;
		if n == 0 {
			return None;
		}
		for &b in &buf[..n] {
			if esc {
				esc = false;
			} else if b == b'\\' {
				esc = true;
			} else if b == b'\n' {
				return Some(line);
			}
			line.push(b);
			if line.len() > 1 << 20 {
				return None;
			}
		}
	}
}

// ---------------------------------------------------------------- run loop

impl Service {
	fn start_tasks(self: &Rc<Self>, listener: Option<UnixListener>) -> Result<()> {
		// signals: CHLD wakes the supervisor, TERM => exit, HUP => restart
		let mut sigs = vec![Signal::Child, Signal::Term, Signal::Hup];
		if self.init.foreground {
			sigs.push(Signal::Int);
		}
		let mut signals = Signals::new(sigs).stack()?;
		let me = self.clone();
		self.ex
			.spawn(async move {
				while let Some(Ok(sig)) = signals.next().await {
					match sig {
						Signal::Child => {
							me.changed.notify(usize::MAX);
						}
						Signal::Term | Signal::Int => {
							let m = me.clone();
							me.ex
								.spawn(async move {
									m.note("SIGTERM: exit");
									let mut out = Vec::new();
									m.do_stop(&Cmd::default(), StopMode::Exit, &mut out).await;
								})
								.detach();
						}
						Signal::Hup => {
							let m = me.clone();
							me.ex
								.spawn(async move {
									m.note("SIGHUP: restart");
									let mut out = Vec::new();
									m.do_restart(&Cmd::default(), &mut out).await;
								})
								.detach();
						}
						_ => {}
					}
				}
			})
			.detach();

		// supervisor
		let me = self.clone();
		self.ex
			.spawn(async move {
				loop {
					let l = me.changed.listen();
					me.tick();
					if me.shutdown.get() {
						break;
					}
					let period = if me.st.borrow().exit_at.is_some() { 100 } else { 1000 };
					or(
						async { l.await; },
						async { Timer::after(Duration::from_millis(period)).await; },
					).await;
				}
			})
			.detach();

		// accept loop (none with -p none)
		let Some(listener) = listener else { return Ok(()) };
		listener.set_nonblocking(true).stack()?;
		let listener = Async::new(listener).stack()?;
		let me = self.clone();
		self.ex
			.spawn(async move {
				loop {
					match listener.accept().await {
						Ok((s, _)) => {
							let m = me.clone();
							me.ex.spawn(async move { m.handle(s).await }).detach();
						}
						Err(e) => {
							me.note(&format!("accept: {e}"));
							Timer::after(Duration::from_millis(200)).await;
						}
					}
				}
			})
			.detach();
		Ok(())
	}

	fn main_loop(self: &Rc<Self>, listener: Option<UnixListener>) -> Result<()> {
		let me = self.clone();
		let ex = self.ex.clone();
		smol::block_on(ex.run(async move {
			me.start_tasks(listener).stack()?;
			if let Err(e) = sys::become_reaper() {
				me.note(&format!("unable to become the reaper for its children: {e}"));
			}
			// initial start
			match me.spawn() {
				Ok(pid) => me.note(&format!("Starting pid {pid}")),
				Err(e) => me.note(&format!("start failed: {e}")),
			}
			me.changed.notify(usize::MAX);
			while !me.shutdown.get() {
				let l = me.changed.listen();
				if me.shutdown.get() {
					break;
				}
				l.await;
			}
			Ok::<(), stacked_errors::Error>(())
		}))
	}
}

// ---------------------------------------------------------------- init

/// `init <label> <command...>`: set up pid file, socket, detach, run.
/// Returns the process exit code (the parent returns right after fork).
pub fn init(cmd: Cmd) -> Result<i32> {
	let Some(label) = cmd.label.clone() else {
		bail!("init requires a label and command");
	};
	if cmd.ext.is_empty() {
		bail!("init requires a label and command");
	}
	paths::check_label(&label).stack()?;

	let root = sys::geteuid() == 0;
	if !root {
		for (set, what) in [
			(cmd.user.is_some(), "-u"),
			(cmd.group.is_some(), "-g"),
			(!cmd.groups.is_empty(), "-G"),
			(cmd.rootdir.is_some(), "-c"),
			(cmd.jaildir.is_some(), "-j"),
			(cmd.mountdev, "-m"),
		] {
			if set {
				sys::require_root(what).stack()?;
			}
		}
	}
	if cmd.rootdir.is_some() && cmd.jaildir.is_some() {
		bail!("-c and -j are exclusive");
	}

	// directory: -p none | -p dir | default
	let dir: Option<PathBuf> = match cmd.piddir.as_deref() {
		Some("none") => None,
		Some(p) => Some(PathBuf::from(p)),
		None => {
			let d = paths::default_dir().stack()?;
			if !root {
				paths::ensure_local_dir(&d).stack()?;
			}
			Some(d)
		}
	};
	if dir.is_none() && !(cmd.foreground && cmd.exit_mode) {
		bail!("-p none requires both -f and -x");
	}

	println!("initializing new service: {label}");

	// pid file (locked for the lifetime of the demon) and listen socket
	let mut pidfile: Option<File> = None;
	let mut listener: Option<UnixListener> = None;
	let mut files: Option<(PathBuf, PathBuf)> = None;
	if let Some(dir) = &dir {
		let pid_p = paths::pid_path(dir, &label);
		let sock_p = paths::sock_path(dir, &label);
		paths::check_sock_len(&sock_p).stack()?;
		let f = OpenOptions::new()
			.read(true)
			.write(true)
			.create(true)
			.truncate(false)
			.mode(0o644)
			.open(&pid_p)
			.stack_err_with(|| format!("cannot open {}", pid_p.display()))?;
		if !sys::try_lock_exclusive(&f).stack()? {
			bail!("service {label} is already running (cannot lock {})", pid_p.display());
		}
		f.set_len(0).stack()?;
		// we hold the lock, so any socket file is stale
		match std::fs::remove_file(&sock_p) {
			Ok(()) => {}
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
			Err(e) => return Err(e).stack_err_with(|| format!("cannot remove {}", sock_p.display())),
		}
		let l = UnixListener::bind(&sock_p).stack_err_with(|| format!("cannot bind {}", sock_p.display()))?;
		// root services are readable by everybody (the demon checks the
		// peer uid); user services stay private
		let mode = if root { 0o666 } else { 0o600 };
		std::fs::set_permissions(&sock_p, std::fs::Permissions::from_mode(mode)).stack()?;
		pidfile = Some(f);
		listener = Some(l);
		files = Some((pid_p, sock_p));
	}

	let cleanup = |files: &Option<(PathBuf, PathBuf)>| {
		if let Some((p, s)) = files {
			let _ = std::fs::remove_file(s);
			let _ = std::fs::remove_file(p);
		}
	};

	// things that may fail are done before fork so errors reach the terminal
	if cmd.mountdev {
		let d = cmd.jaildir.as_deref().or(cmd.rootdir.as_deref());
		if let Some(d) = d && let Err(e) = sys::devfs_mount(d) {
			cleanup(&files);
			return Err(e).stack();
		}
	}
	let logsink = match cmd.logfile.as_deref() {
		Some("/dev/null") => None,
		Some(p) => match open_logfile(p) {
			Ok(f) => Some(f),
			Err(e) => {
				cleanup(&files);
				return Err(e).stack();
			}
		},
		None if cmd.foreground => Some(sys::dup_stdout().stack()?),
		None => None,
	};

	// detach
	if !cmd.foreground {
		let (rd, wr) = sys::pipe_cloexec().stack()?;
		// SAFETY: no threads exist yet (no smol primitive has been created).
		let pid = match unsafe { sys::fork() } {
			Ok(p) => p,
			Err(e) => {
				cleanup(&files);
				return Err(e).stack();
			}
		};
		if pid != 0 {
			// parent: record the demon's pid, wait until it has detached
			drop(wr);
			if let Some(f) = &mut pidfile {
				f.write_all(format!("{pid}\n").as_bytes()).stack()?;
			}
			println!("{pid}");
			let mut rdf = File::from(rd);
			let mut b = [0u8; 1];
			return match rdf.read(&mut b) {
				Ok(1) => Ok(0),
				_ => {
					eprintln!("service {label} failed to start");
					Ok(1)
				}
			};
		}
		// child: the service demon
		drop(rd);
		sys::setsid().stack()?;
		sys::redirect_stdio_null(false).stack()?;
		let mut w = File::from(wr);
		let _ = w.write_all(&[1]);
	} else if let Some(f) = &mut pidfile {
		f.write_all(format!("{}\n", sys::getpid()).as_bytes()).stack()?;
	}

	match &cmd.proctitle {
		Some(t) => sys::set_title(&format!("{label} - {t}")),
		None => sys::set_title(&label),
	}

	let ex = Rc::new(LocalExecutor::new());
	let svc = Service::new(cmd.clone(), ex);
	svc.log.borrow_mut().set_sink(logsink);

	let res = svc.main_loop(listener);

	// shutdown: leave no files, no devfs mount behind
	cleanup(&files);
	if cmd.mountdev && let Some(d) = cmd.jaildir.as_deref().or(cmd.rootdir.as_deref()) {
		let _ = sys::devfs_unmount(d);
	}
	drop(pidfile);
	res.map(|()| 0)
}

/// Is the pid file locked, i.e. is a demon alive for this label?
pub fn demon_alive(pidfile: &Path) -> bool {
	match OpenOptions::new().read(true).write(true).open(pidfile) {
		Ok(f) => matches!(sys::try_lock_exclusive(&f), Ok(false)),
		Err(_) => false,
	}
}
