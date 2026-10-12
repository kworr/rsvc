//! End-to-end smoke tests: run the real binary against a private directory.
//! Linux uses the /proc based reaper stub; behaviour must match the spec.

use std::path::PathBuf;
use std::process::{Command, Output};
use std::thread::sleep;
use std::time::{Duration, Instant};

struct Env {
    dir: PathBuf,
}

impl Env {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("rsvc-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Env { dir }
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_rsvc"))
            .arg("-p")
            .arg(&self.dir)
            .args(args)
            .output()
            .unwrap()
    }

    fn out(&self, args: &[&str]) -> (i32, String) {
        let o = self.run(args);
        (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into_owned())
    }

    fn wait_for(&self, args: &[&str], want: &str) {
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            let (_, o) = self.out(args);
            if o.contains(want) {
                return;
            }
            assert!(Instant::now() < end, "timeout waiting for {want:?}, last output {o:?}");
            sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = self.run(&["kill", "all"]);
        sleep(Duration::from_millis(500));
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn lifecycle_and_status_codes() {
    let e = Env::new("life");
    assert_eq!(e.out(&["init", "web", "sleep", "300"]).0, 0);
    e.wait_for(&["status", "web"], "running");
    assert_eq!(e.out(&["status", "web"]).0, 0);
    assert_eq!(e.out(&["status", "nosuch"]).0, 2);

    assert_eq!(e.out(&["stop", "web"]).0, 0);
    let (rc, o) = e.out(&["status", "web"]);
    assert_eq!(rc, 1);
    assert!(o.contains("stopped (manual)"), "{o}");
    // stop is idempotent and does not hang
    assert_eq!(e.out(&["stop", "web"]).0, 0);

    assert_eq!(e.out(&["start", "web"]).0, 0);
    assert!(e.out(&["start", "web"]).1.contains("Already started"));
    assert_eq!(e.out(&["restart", "web"]).0, 0);
    e.wait_for(&["status", "web"], "running");

    // prefix match and `all`
    assert!(e.out(&["list", "w"]).1.contains("web"));
    assert!(e.out(&["list", "all"]).1.contains("web"));

    assert_eq!(e.out(&["exit", "web"]).0, 0);
    let end = Instant::now() + Duration::from_secs(10);
    while e.dir.join("service.web.sk").exists() {
        assert!(Instant::now() < end, "demon did not remove its files");
        sleep(Duration::from_millis(100));
    }
    assert!(!e.dir.join("service.web.pid").exists());
}

#[test]
fn failing_exec_does_not_wedge_stop() {
    let e = Env::new("bad");
    assert_eq!(e.out(&["-r", "30", "init", "bad", "/nonexistent/prog"]).0, 0);
    e.wait_for(&["log", "bad"], "start failed");
    let t = Instant::now();
    assert_eq!(e.out(&["stop", "bad"]).0, 0);
    assert!(t.elapsed() < Duration::from_secs(5));
}

#[test]
fn restart_limit_trips_and_manual_start_recovers() {
    let e = Env::new("flap");
    assert_eq!(e.out(&["-r", "1", "-F", "2:60", "init", "flap", "sh", "-c", "exit 3"]).0, 0);
    e.wait_for(&["status", "flap"], "stopped (failed)");
    assert_eq!(e.out(&["start", "flap"]).0, 0);
}

#[test]
fn term_ignored_gets_killed() {
    let e = Env::new("term");
    assert_eq!(
        e.out(&["-R", "1", "-t", "1", "init", "stub", "sh", "-c", "trap '' TERM; while :; do sleep 1; done"]).0,
        0
    );
    e.wait_for(&["status", "stub"], "running");
    let t = Instant::now();
    assert_eq!(e.out(&["stop", "stub"]).0, 0);
    assert!(t.elapsed() >= Duration::from_millis(900) && t.elapsed() < Duration::from_secs(8));
    assert_eq!(e.out(&["status", "stub"]).0, 1);
}

#[test]
fn log_dot_lines_survive() {
    let e = Env::new("dots");
    assert_eq!(e.out(&["init", "dots", "sh", "-c", "printf '.\\n..\\nx\\n'; sleep 100"]).0, 0);
    e.wait_for(&["log", "dots"], "x\n");
    let (_, o) = e.out(&["log", "dots"]);
    assert!(o.contains("\n.\n..\nx\n"), "{o:?}");
}

#[test]
fn directive_needs_label() {
    let e = Env::new("nolabel");
    let (rc, o) = e.out(&["exit"]);
    assert_eq!(rc, 1);
    assert!(o.contains("requires a label"), "{o}");
}
