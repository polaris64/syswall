mod child_process;
mod cli;
mod process_conf;
mod process_state;
mod syscalls;

use std::env;
use nix::sys::ptrace;
use nix::unistd;

use crate::process_conf::ProcessConf;

fn main() -> Result<(), String> {
    let mut args = env::args();
    
    // Get first argument if possible (child command)
    let child_cmd = args.nth(1).ok_or("Please specify the name and arguments for the child process to execute")?;

    // Fork this process
    let fork_res = unistd::fork().map_err(|_| "Unable to fork")?;

    match fork_res {
        unistd::ForkResult::Parent{ child } => {
            eprintln!("Tracing child process {} ({})", child, child_cmd);

            // Wait for child and set trace options
            child_process::wait_child(child)?;
            ptrace::setoptions(child, ptrace::Options::PTRACE_O_EXITKILL)
                .map_err(|_| "Unable to set PTRACE_O_EXITKILL option for child process")?;

            // TODO: read config filename from args
            let conf_file = "test.json";
            let mut conf = match ProcessConf::from_file(conf_file) {
                Ok(c) => {
                    eprintln!("Configuration loaded from {}", conf_file);
                    c
                },
                Err(e) => {
                    eprintln!("ERROR: unable to read process configuration from file {}: {}", conf_file, e);
                    ProcessConf::new()
                },
            };

            // Execute main child process control loop
            match child_process::child_loop(child, &mut conf) {
                Ok(st) => {
                    // Print the child process's final state report
                    eprintln!("{}", st.report());

                    // TODO: save the process config based on args
                    if let Err(e) = conf.write_to_file(conf_file) {
                        eprintln!("ERROR: unable to write process configuration to file {}: {}", conf_file, e);
                    }
                },
                Err(e) => eprintln!("ERROR: errur during processing of child loop: {}", e),
            };
        },
        unistd::ForkResult::Child => {
            child_process::exec_child(child_cmd, args).map_err(|_| "Unable to execute child process")?;
        },
    };

    Ok(())
}
