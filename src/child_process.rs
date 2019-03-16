use log::{debug, info, trace, warn};
use nix::sys::ptrace;
use nix::sys::signal;
use nix::sys::uio;
use nix::sys::wait;
use nix::unistd::{execvp, Pid};
use signal_hook;
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::app::App;
use crate::platforms::PlatformHandler;
use crate::process_conf::ProcessConf;
use crate::process_state::{ProcessState, ProcessTraceState, ProcessType};
use crate::syscalls;

pub struct ProcessList(pub HashMap<Pid, ProcessState>);

impl ProcessList {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    /// Returns a flag which is set if all processes are of type ClonedThread
    pub fn all_threads(&self, tracee_pid: Pid) -> bool {
        self.0.iter().all(|(pid, child_state)| {
            *pid == tracee_pid
                || match child_state.process_type {
                    ProcessType::ClonedThread => true,
                    _ => false,
                }
        })
    }

    /// Returns a flag which is set if all processes are Terminated
    pub fn all_terminated(&self) -> bool {
        self.0.values().map(|x| &x.trace_state).all(|x| match x {
            ProcessTraceState::Terminated(_) => true,
            _ => false,
        })
    }
}

#[derive(Debug)]
pub struct ChildProcessBuffer(pub Vec<u8>);

impl From<ChildProcessBuffer> for String {
    fn from(b: ChildProcessBuffer) -> String {
        String::from_utf8_lossy(&b.0).into_owned()
    }
}

/// Reads a given amount child process memory into a ChildProcessBuffer
///
/// # Arguments
///
///   - pid: PID of the target child process
///   - base: base VM address for read
///   - len: length (in bytes) of read
pub fn get_child_buffer(
    pid: Pid,
    base: usize,
    len: usize,
) -> Result<ChildProcessBuffer, &'static str> {
    let mut rbuf: Vec<u8> = vec![0; len];
    let remote_iovec = uio::RemoteIoVec { base, len };
    uio::process_vm_readv(
        pid,
        &[uio::IoVec::from_mut_slice(rbuf.as_mut_slice())],
        &[remote_iovec],
    )
    .map_err(|_| "Unable to read from child process virtual memory")?;
    Ok(ChildProcessBuffer(rbuf))
}

/// Reads a null-terminated string from child process memory into a ChildProcessBuffer
///
/// # Arguments
///
///   - pid: PID of the target child process
///   - base: base VM address for read
pub fn get_child_buffer_cstr(pid: Pid, base: usize) -> Result<String, &'static str> {
    let mut final_buf: Vec<u8> = Vec::with_capacity(255);

    // Current RemoteIoVec base address
    let mut current_base = base;

    // Index of 0 byte in final_buf
    let mut nul_idx: isize = -1;

    // Keep reading 255-byte chunks from the process VM until one contains a 0 byte
    // (null-termination character)
    loop {
        // Read into a temporary buffer
        let mut rbuf: Vec<u8> = vec![0; 255];
        let remote_iovec = uio::RemoteIoVec {
            base: current_base,
            len: 255,
        };
        uio::process_vm_readv(
            pid,
            &[uio::IoVec::from_mut_slice(rbuf.as_mut_slice())],
            &[remote_iovec],
        )
        .map_err(|_| "Unable to read from child process virtual memory")?;

        // Append temporary buffer to the final buffer and increase base address pointer
        final_buf.append(&mut rbuf);
        current_base += 255;

        // If final_buf contains a 0 byte, store the index and break from the read loop
        if final_buf.contains(&0) {
            if let Some(idx) = final_buf.iter().position(|&x| x == 0) {
                nul_idx = idx as isize;
            }
            break;
        }
    }
    if nul_idx > -1 {
        Ok(String::from_utf8_lossy(&final_buf[0..(nul_idx as usize)]).into_owned())
    } else {
        Err("Null-terminated string not found")
    }
}

/// Executes a child process under ptrace using execvp.
///
/// Should be called by the tracer child process after forking.
///
/// Arguments
///
///   - cmd: command ard argv for execvp()
pub fn exec_child(cmd: Vec<&str>) -> Result<(), String> {
    ptrace::traceme()
        .map_err(|_| "CHILD: could not enable tracing by parent (PTRACE_TRACEME failed)")?;

    // Extract child command (first arg)
    let child_cmd = CString::new(*cmd.first().ok_or("Unable to extract tracee command")?)
        .map_err(|_| "Unable to extract tracee command")?;

    // Extract child arguments (including first command)
    let child_args = cmd
        .iter()
        .map(|v| CString::new(*v).unwrap_or_default())
        .collect::<Vec<CString>>();

    debug!(
        "CHILD: executing {:?} with argv {:?}...",
        child_cmd, child_args
    );
    execvp(&child_cmd, &child_args).map_err(|e| format!("unable to execute {:?}: {}", child_cmd, e))?;
    Ok(())
}

/// Waits for a child process event.
///
/// Will block until an event is ready unless `nohang` is set
///
/// Arguments
///
///   - pid: child process PID, or -1 to wait for all child processes
///   - nohang: if set, function will not block if all child processes are running
pub fn wait_child(pid: Pid, nohang: bool) -> Result<nix::sys::wait::WaitStatus, String> {
    if nohang {
        wait::waitpid(
            pid,
            Some(wait::WaitPidFlag::__WALL | wait::WaitPidFlag::WNOHANG),
        )
        .map_err(|e| format!("Unable to wait for child PID {}: {:?}", pid, e))
    } else {
        wait::waitpid(pid, Some(wait::WaitPidFlag::__WALL))
            .map_err(|e| format!("Unable to wait for child PID {}: {:?}", pid, e))
    }
}

/// Handles a syscall ptrace event for a child process
///
/// Arguments
///
///   - child: ProcessState of the child process receiving the event
///   - pid: PID of the child process receiving the event
///   - app: main application configuration
///   - conf: tracer configuration, which will be modified based on user responses to syscall
///   - platform_handler: platform-specific handler used to deal with syscall entry/exit
fn handle_pid_syscall(
    child: &mut ProcessState,
    pid: Pid,
    app: &App,
    conf: &mut ProcessConf,
    platform_handler: &impl PlatformHandler,
) -> Result<(), String> {
    match child.trace_state {

        // Event must be a syscall-enter-stop
        ProcessTraceState::RunningAwaitSyscall => {
            child.trace_state = ProcessTraceState::TraceSyscallEnterStop;

            // Get syscall details
            match ptrace::getregs(pid) {
                Ok(mut regs) => {
                    let syscall_id = regs.orig_rax;

                    child.syscall_id = Some(syscall_id);
                    child.handler_res = Some(syscalls::handle_pre_syscall(
                        app,
                        conf,
                        child,
                        platform_handler,
                        pid,
                        &mut regs,
                    ));

                    // Execute this child syscall
                    ptrace::syscall(pid)
                        .map_err(|_| format!("Unable to restart syscall exit for PID {:?}", pid))
                }
                Err(err) => {
                    if err.as_errno() == Some(nix::errno::Errno::ESRCH) {
                        // If ESRCH error is received, child PID must no longer be running, so set
                        // to Terminated
                        child.trace_state = ProcessTraceState::Terminated(-1);
                        Ok(())
                    } else {
                        Err(String::from(
                            "Unable to get syscall registers after servicing",
                        ))
                    }
                }
            }
        }

        // Event must be a syscall-exit-stop
        ProcessTraceState::TraceSyscallEnterStop => {
            child.trace_state = ProcessTraceState::TraceSyscallExitStop;

            // Get syscall result
            match ptrace::getregs(pid) {
                Ok(ref mut regs) => {
                    syscalls::handle_post_syscall(child, platform_handler, pid, regs);

                    child.syscall_id = None;
                    child.handler_res = None;

                    // Await next child syscall
                    ptrace::syscall(pid).map_err(|_| {
                        format!("Unable to restart syscall entry wait for PID {:?}", pid)
                    })?;

                    child.trace_state = ProcessTraceState::RunningAwaitSyscall;
                    Ok(())
                }
                Err(err) => {
                    if err.as_errno() == Some(nix::errno::Errno::ESRCH) {
                        // If ESRCH error is received, child PID must no longer be running, so set
                        // to Terminated
                        child.trace_state = ProcessTraceState::Terminated(-1);
                        Ok(())
                    } else {
                        Err(String::from(
                            "Unable to get syscall registers after servicing",
                        ))
                    }
                }
            }
        }
        _ => Err(format!(
            "Unhandled process state for {:?} ({:?})",
            pid, child.trace_state
        )),
    }
}

/// Handles a stopped ptrace event for a child process
///
/// Arguments
///
///   - child: ProcessState of the child process receiving the event
///   - pid: PID of the child process receiving the event
///   - sig: specific signal received by child process
fn handle_pid_stop(child: &mut ProcessState, pid: Pid, sig: signal::Signal) {
    match sig {
        signal::Signal::SIGTERM => {
            info!("SIGTERM received for PID {:?}", pid);

            // TODO: get exit status
            child.trace_state = ProcessTraceState::Terminated(-1);
        }
        _ => {}
    };
}

/// Handles all WaitStatus types returned by wait_child() for a specific child process
///
/// Arguments
///
///   - wait_status: status returned by wait_child()
///   - processes: ProcessList which can be modified if the child cloned/forked.
///   - app: main application configuration
///   - conf: tracer configuration, which will be modified based on user responses to syscall
///   - platform_handler: platform-specific handler used to deal with syscall entry/exit
fn handle_wait_status(
    wait_status: &wait::WaitStatus,
    processes: &mut ProcessList,
    app: &App,
    conf: &mut ProcessConf,
    platform_handler: &impl PlatformHandler,
) -> Result<(), String> {
    match wait_status {
        // Handle the continuation of a child process after a stop
        wait::WaitStatus::Continued(pid) => {
            info!("Child process {:?} continued", pid);
            Ok(())
        }

        // Handle exit of a child process
        wait::WaitStatus::Exited(pid, code) => {
            info!("Child process {:?} exited with code {}", pid, code);
            let mut child = processes.0.get_mut(&pid).ok_or(format!(
                "Child process {:?} exited, however this process is not in the process list",
                pid
            ))?;
            child.trace_state = ProcessTraceState::Terminated(*code as isize);
            Ok(())
        }

        // Handle ptrace events such as a clone, fork or exec
        wait::WaitStatus::PtraceEvent(pid, sig, ev_type) => {
            // DEBUG: ptrace events should always use a SIGTRAP
            assert!(*sig == signal::Signal::SIGTRAP);

            // Set flag to continue processing based on event type.  Processing fetches the new PID
            // from the event and updates the child ProcessState accordigly, therefore processing
            // should only continue for clones and forks.
            // TODO: stop using Linux hard-coded event IDs
            let cont = match ev_type {
                1 => {
                    info!("Process {:?} forked", pid);
                    true
                }
                2 => {
                    info!("Process {:?} vforked", pid);
                    true
                }
                3 => {
                    info!("Process {:?} created clone", pid);
                    true
                }
                4 => {
                    info!("Process {:?} called exec", pid);
                    false
                }
                t => {
                    warn!("Process {:?}: unknown event type {}", pid, t);
                    false
                }
            };

            if cont {
                let child_pid =
                    ptrace::getevent(*pid).map_err(|_| "Unable to get ptrace event details")?;

                // Get new child PID for clone, fork, etc.
                let child_pid = Pid::from_raw(child_pid as i32);
                info!("New child PID: {:?}", child_pid);

                let child_type = match ev_type {
                    1 => ProcessType::ForkedProcess,
                    2 => ProcessType::VForkedProcess,
                    3 => ProcessType::ClonedThread,
                    _ => ProcessType::ForkedProcess,
                };

                // Update or insert child ProcessState
                processes.0.entry(child_pid)
                    .and_modify(|ch| {
                        if ch.trace_state == ProcessTraceState::Stopped {
                            info!("Changing existing Stopped process {:?} to RunningAwaitSyscall ({:?})...", child_pid, ch);
                            ch.trace_state = ProcessTraceState::RunningAwaitSyscall;
                            ch.process_type = child_type;
                        }
                    })
                    .or_insert_with(|| {
                        info!("Process {:?} does not exist, adding as Created...", child_pid);
                        ProcessState::new(ProcessTraceState::Created, child_type)
                    });
            }

            // Restart PID that sent the event (parent of newly-created PID)
            ptrace::syscall(*pid)
                .map_err(|_| format!("Unable to restart PID {:?} for syscall entry wait", pid))?;

            Ok(())
        }

        // When PTRACE_O_TRACESYSGOOD is set, PtraceSyscall will be generated when a process has
        // hit a syscall entery/exit.  Handle the syscall via handle_pid_syscall().
        wait::WaitStatus::PtraceSyscall(pid) => {
            let child = processes.0.get_mut(&pid).ok_or(format!(
                "Syscall was delivered by {:?} but process was not found in the process list",
                pid
            ))?;
            handle_pid_syscall(child, *pid, app, conf, platform_handler)
        }

        // Handle a generic signal to a child process: log signal and restart child via
        // ptrace::syscall().
        wait::WaitStatus::Signaled(pid, sig, did_core_dump) => {
            info!("Child process {:?} was given signal {:?}", pid, sig);
            if *did_core_dump {
                info!("Child process {:?} produced a core dump", pid);
            }
            ptrace::syscall(*pid)
                .map_err(|_| format!("Unable to restart PID {:?} for syscall entry wait", pid))?;
            Ok(())
        }

        // StillAlive will not be generated unless WNOHANG waitpid() option is set
        wait::WaitStatus::StillAlive => Ok(()),

        // Stopped: handle new PID, PID just created from PtraceEvent or existing PID by
        // (re)starting it via ptrace::syscall().  Also call handle_pid_stop() for existing PIDs to
        // handle any signals as necessary.
        wait::WaitStatus::Stopped(pid, signal) => {
            if !processes.0.contains_key(&pid) {
                // If the PID is not in the ProcessList, add it as ProcessTraceState::Stopped and
                // start it via ptrace::syscall().  State will be changed to RunningAwaitSyscall
                // when the PtraceEvent eventually arrives.
                trace!("New process (stopped): {:?}", pid);
                processes.0.insert(
                    *pid,
                    ProcessState::new(ProcessTraceState::Stopped, ProcessType::ForkedProcess),
                );
                ptrace::syscall(*pid).map_err(|_| {
                    format!("Unable to start new PID {:?} for syscall entry wait", pid)
                })?;
            } else if let Some(mut child) = processes.0.get_mut(&pid) {
                if child.trace_state == ProcessTraceState::Created {
                    // If process has already been created via a WaitStatus::PtraceEvent, start it
                    // via ptrace::syscall() and change its ProcessTraceState.
                    trace!(
                        "PID {:?} was previously marked as created, setting to RunningAwaitSyscall...",
                        pid
                    );
                    ptrace::syscall(*pid).map_err(|_| {
                        format!(
                            "Unable to start newly-created PID {:?} for syscall entry wait",
                            pid
                        )
                    })?;
                    child.trace_state = ProcessTraceState::RunningAwaitSyscall;
                } else {
                    // If the process already exists and is running, handle the signal and restart
                    // it
                    handle_pid_stop(child, *pid, *signal);
                    ptrace::syscall(*pid).map_err(|_| {
                        format!(
                            "Unable to start newly-created PID {:?} for syscall entry wait",
                            pid
                        )
                    })?;
                }
            };
            Ok(())
        }
    }
}

/// Initiates and runs the main tracer loop on a child (tracee) PID
///
/// Arguments
///
///   - app: main application configuration
///   - tracee_pid: PID of the main tracee process (which should have been executed via exec_child())
///   - platform_handler: platform-specific handler used to deal with syscalls
///   - conf: tracer configuration
pub fn child_loop(
    app: &App,
    tracee_pid: Pid,
    platform_handler: impl PlatformHandler,
    conf: &mut ProcessConf,
) -> Result<ProcessList, String> {
    let mut processes: ProcessList = ProcessList::new();

    // Flag to indicate if a SIGINT has been received
    let sigint = Arc::new(AtomicBool::new(false));

    // UNSAFE: register a handler for SIGINT to close stdin and set the "sigint" flag
    unsafe {
        // Clone the "sigint" Arc to move to closure
        let sigint = Arc::clone(&sigint);

        signal_hook::register(signal_hook::SIGINT, move || {
            // Close stdin explicitly. This will abort any user input (io::stdin().read_line())
            // that is currently in progress.
            //
            // TODO: improve when support is available (see:
            // https://github.com/rust-lang/rust/issues/40032)
            libc::close(0);

            // Set the "sigint" flag
            sigint.store(true, Ordering::SeqCst);
        })
    }
    .map_err(|_| "Unable to register SIGINT handler")?;

    // Insert main tracee process into ProcessList
    processes.0.insert(
        tracee_pid,
        ProcessState::new(
            ProcessTraceState::RunningAwaitSyscall,
            ProcessType::MainTracee,
        ),
    );

    // Main tracing loop
    loop {
        // Check "sigint" flag: if set, kill the tracee process and break from the loop
        if sigint.load(Ordering::Relaxed) {
            warn!("SIGINT received, killing tracee process...");
            if let Err(e) = signal::kill(tracee_pid, signal::Signal::SIGTERM) {
                warn!("Unable to send SIGTERM to tracee process: {}", e);
            }
            if let Err(e) = signal::kill(tracee_pid, signal::Signal::SIGKILL) {
                warn!("Unable to send SIGKILL to tracee process: {}", e);
            }
            break;
        }

        // Wait for any child process (-1)
        let wait_status = wait_child(Pid::from_raw(-1 as i32), false);
        if let Ok(ws) = wait_status {
            if let Err(s) = handle_wait_status(&ws, &mut processes, app, conf, &platform_handler) {
                warn!("{}", s);
                break;
            }
        } else {
            warn!("{:?}", wait_status);
            break;
        }

        // If main process contains only clones (threads) then break from loop when this process
        // terminates.  Otherwise (e.g. forks), only break when all processes have terminated.
        if let Some(main_child) = processes.0.get(&tracee_pid) {
            if let ProcessTraceState::Terminated(main_exit_status) = main_child.trace_state {
                // Check if all child processes are ClonedThread
                let mut exit = false;
                if processes.all_threads(tracee_pid) {
                    info!("All remaining processes are threads, exiting trace loop...");
                    exit = true;
                } else if processes.all_terminated() {
                    info!("All processes are now terminated, exiting trace loop...");
                    exit = true;
                }

                if exit {
                    info!(
                        "Main tracee process {:?} has terminated with code {}",
                        tracee_pid, main_exit_status
                    );
                    break;
                }
            }
        }
    }

    Ok(processes)
}
