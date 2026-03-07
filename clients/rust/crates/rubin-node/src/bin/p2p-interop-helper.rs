use std::env;
use std::io::{self, Write};
use std::process;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let exit_code = match rubin_node::interop::run_cli_with_ready(&args, |addr| {
        println!("READY {addr}");
        io::stdout().flush().map_err(|err| err.to_string())
    }) {
        Ok(()) => 0,
        Err(err) => {
            let _ = writeln!(io::stderr(), "{err}");
            1
        }
    };
    process::exit(exit_code);
}
