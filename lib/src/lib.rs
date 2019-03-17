mod child_process;
mod platforms;
mod process_state;
mod syscalls;
pub mod tracer_conf;
pub mod user_response;

use log::info;
use nix::sys::ptrace;
use nix::unistd;

use crate::platforms::linux_x86_64::Handler;
use crate::tracer_conf::{RuntimeConf, TracerConf};

pub fn trace(cmd: Vec<&str>, conf: &mut TracerConf, runtime_conf: &RuntimeConf) -> Result<child_process::ProcessList, String> {
    // Create a syscall PlatformHandler
    let platform_handler = Handler::new();

    // Fork this process
    let fork_res = unistd::fork().map_err(|_| "Unable to fork")?;

    match fork_res {
        unistd::ForkResult::Parent { child } => {
            info!("Tracing child process {} ({:?})", child, cmd);

            // Wait for child and set trace options
            child_process::wait_child(child, false)?;
            ptrace::setoptions(
                child,
                ptrace::Options::PTRACE_O_EXITKILL
                    
                    // Trace sub-processes of tracee
                    | ptrace::Options::PTRACE_O_TRACECLONE
                    | ptrace::Options::PTRACE_O_TRACEFORK
                    | ptrace::Options::PTRACE_O_TRACEVFORK
                    | ptrace::Options::PTRACE_O_TRACEVFORKDONE

                    | ptrace::Options::PTRACE_O_TRACEEXEC

                    // PTRACE_O_TRACESYSGOOD: recommended by strace README-linux-ptrace. Causes
                    // WaitStatus::PtraceSyscall to be generated instead of WaitStatus::Stopped
                    // upon syscall in tracee.
                    | ptrace::Options::PTRACE_O_TRACESYSGOOD,

                    // PTRACE_O_TRACEEXIT will stop the tracee before exit in order to examine
                    // registers. This is not required; without this option the tracer will be notified
                    // after tracee exit.
                    // ptrace::Options::PTRACE_O_TRACEEXIT
            )
            .map_err(|_| "Unable to set PTRACE_O_* options for child process")?;

            // Await next child syscall for main tracee
            ptrace::syscall(child)
                .map_err(|_| "Unable to set child process to run until first syscall")?;

            // Execute main child process control loop
            child_process::child_loop(child, platform_handler, conf, runtime_conf)
        }
        unistd::ForkResult::Child => {
            child_process::exec_child(cmd).map_err(|_| "Unable to execute child process")?;
            Ok(child_process::ProcessList::new())
        }
    }
}
