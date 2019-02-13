mod child_process;
mod cli;
mod process_state;
mod syscalls;

use std::env;
use nix::sys::ptrace;
use nix::unistd;

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

            // Execute main child process control loop
            match child_process::child_loop(child) {
                Ok(st) => {
                    // Print the child process's final state report
                    eprintln!("{}", st.report());
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
