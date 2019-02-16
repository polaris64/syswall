mod app;
mod child_process;
mod logger;
mod platforms;
mod process_conf;
mod process_state;
mod syscalls;

use log::{debug, error, info, warn};
use nix::sys::ptrace;
use nix::unistd;

use crate::app::App;
use crate::platforms::linux_x86_64::Handler;
use crate::process_conf::ProcessConf;

fn main() -> Result<(), String> {
    let app = App::new();

    // Get the tracee command as a Vec<&str>
    let child_cmd = app
        .args
        .values_of("tracee_cmd")
        .ok_or("Unable to get tracee command")?
        .collect::<Vec<&str>>();

    // Create a syscall PlatformHandler
    let platform_handler = Handler::new();

    // Fork this process
    let fork_res = unistd::fork().map_err(|_| "Unable to fork")?;

    match fork_res {
        unistd::ForkResult::Parent { child } => {
            info!("Tracing child process {} ({:?})", child, child_cmd);

            // Wait for child and set trace options
            child_process::wait_child(child)?;
            ptrace::setoptions(child, ptrace::Options::PTRACE_O_EXITKILL)
                .map_err(|_| "Unable to set PTRACE_O_EXITKILL option for child process")?;

            // Load ProcessConf from file if necessary
            let mut conf: ProcessConf = if app.args.is_present("load_config") {
                match app.args.value_of("config_file") {
                    Some(filename) => match ProcessConf::from_file(filename) {
                        Ok(c) => {
                            debug!("Configuration loaded from {}", filename);
                            c
                        }
                        Err(e) => {
                            error!(
                                "Unable to read process configuration from file {}: {}",
                                filename, e
                            );
                            ProcessConf::new()
                        }
                    },
                    None => ProcessConf::new(),
                }
            } else {
                ProcessConf::new()
            };

            // Execute main child process control loop
            match child_process::child_loop(&app, child, platform_handler, &mut conf) {
                Ok(st) => {
                    // Print the child process's final state report
                    info!("\nFinal child process state: -\n{}", st.report().as_str());

                    // Save the process config based on args
                    if app.args.is_present("save_config") {
                        match app.args.value_of("config_file") {
                            Some(filename) => {
                                if let Err(e) = conf.write_to_file(filename) {
                                    error!("Unable to write process configuration to file {}: {}", filename, e);
                                }
                            },
                            None => warn!("The program was requested to save the tracee configuration, but no filename was specified"),
                        };
                    }
                }
                Err(e) => error!("Error during processing of child loop: {}", e),
            };
        }
        unistd::ForkResult::Child => {
            child_process::exec_child(child_cmd).map_err(|_| "Unable to execute child process")?;
        }
    };

    Ok(())
}
