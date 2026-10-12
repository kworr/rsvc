use stacked_errors::Result;

fn real_main() -> Result<i32> {
	let args: Vec<String> = std::env::args().skip(1).collect();
	let cmd = match rsvc::opts::parse(args.clone()) {
		Ok(c) => c,
		Err(e) => {
			eprintln!("{e}");
			return Ok(1);
		}
	};
	if cmd.directive == "init" {
		// must run before any async runtime exists (fork)
		rsvc::daemon::init(cmd)
	} else {
		rsvc::client::run(cmd, &args)
	}
}

fn main() {
	match real_main() {
		Ok(rc) => std::process::exit(rc),
		Err(e) => {
			eprintln!("rsvc: {e}");
			std::process::exit(1);
		}
	}
}
