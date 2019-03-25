mod child_process;
mod platforms;
mod process_state;
mod syscalls;
pub mod tracer_conf;
pub mod user_response;

use log::info;
use nix::sys::ptrace;
use nix::unistd;

use crate::child_process::ProcessList;
use crate::platforms::linux_x86_64::Handler;
use crate::syscalls::SyscallHandler;
use crate::tracer_conf::{RuntimeConf, TracerConf};

/// Main syswall tracing function: allows a child process to be executed and traced by syswall
///
/// [`ProcessList`]: ./child_process/struct.ProcessList.html
/// [`RuntimeConf`]: ./tracer_conf/struct.RuntimeConf.html
/// [`TracerConf`]: ./tracer_conf/struct.TracerConf.html
///
/// When called, the current process will fork and the child will execute `cmd`.  The parent will
/// then enter the trace loop which processes the syscalls for the child (tracee) process.  When
/// the child process terminates, this function will return.
///
/// # Arguments
///
///   - `cmd`: command and arguments used for running the child process (e.g. ["ls", "-l"])
///   - `conf`: [`TracerConf`] instance which will be used and modified during the trace
///   - `runtime_conf`: [`RuntimeConf`] instance which provides details of the runtime interface
///
/// # Returns
///
/// Upon success, returns an Ok([`ProcessList`]) containing the states of all tracee processes.
///
/// # Example
///
/// ```
/// use syswall::trace;
/// use syswall::tracer_conf::{RuntimeConf, TracerConf};
///
/// let cmd = vec!["ls", "-l"];
/// let mut conf = TracerConf::default();
/// let runtime_conf = RuntimeConf::default();
/// if let Ok(process_states) = trace(cmd, &mut conf, &runtime_conf) {
///     // Handle final process status reports
/// }
/// ```
pub fn trace(cmd: Vec<&str>, conf: &mut TracerConf, runtime_conf: &RuntimeConf) -> Result<ProcessList, String> {
    let mut syscall_handler = SyscallHandler::new(
        conf, runtime_conf, Box::new(Handler::new()),
    );

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
            child_process::child_loop(child, &mut syscall_handler)
        }
        unistd::ForkResult::Child => {
            child_process::exec_child(cmd).map_err(|_| "Unable to execute child process")?;
            Ok(ProcessList::default())
        }
    }
}
