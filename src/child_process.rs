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

    pub fn all_threads(&self, tracee_pid: Pid) -> bool {
        self.0.iter().all(|(pid, child_state)| {
            *pid == tracee_pid
                || match child_state.process_type {
                    ProcessType::ClonedThread => true,
                    _ => false,
                }
        })
    }

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
    execvp(&child_cmd, &child_args).map_err(|_| format!("unable to execute {:?}", child_cmd))?;
    Ok(())
}

pub fn wait_child(pid: Pid) -> Result<nix::sys::wait::WaitStatus, String> {
    wait::waitpid(pid, Some(wait::WaitPidFlag::__WALL))
        .map_err(|e| format!("Unable to wait for child PID {}: {:?}", pid, e))
}

fn handle_pid_stop(
    child: &mut ProcessState,
    pid: Pid,
    sig: nix::sys::signal::Signal,
    app: &App,
    conf: &mut ProcessConf,
    platform_handler: &impl PlatformHandler,
) -> Result<(), String> {
    match sig {
        nix::sys::signal::Signal::SIGTRAP => {
            match child.trace_state {
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
                            ptrace::syscall(pid).map_err(|_| {
                                format!("Unable to restart syscall exit for PID {:?}", pid)
                            })?;
                        }
                        Err(err) => {
                            if err.as_errno() == Some(nix::errno::Errno::ESRCH) {
                                child.trace_state = ProcessTraceState::Terminated(-1);
                            } else {
                                warn!("Unable to get syscall registers after servicing");
                            }
                        }
                    }
                }
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
                        }
                        Err(err) => {
                            if err.as_errno() == Some(nix::errno::Errno::ESRCH) {
                                child.trace_state = ProcessTraceState::Terminated(-1);
                            } else {
                                warn!("Unable to get syscall registers after servicing");
                            }
                        }
                    };
                }
                _ => {
                    warn!("STUB: Unhandled process state ({:?})", pid);
                }
            };
            Ok(())
        }
        nix::sys::signal::Signal::SIGSTOP => {
            ptrace::syscall(pid)
                .map_err(|_| format!("Unable to restart PID {:?} for syscall entry wait", pid))?;
            Ok(())
        }
        nix::sys::signal::Signal::SIGCHLD => {
            ptrace::syscall(pid)
                .map_err(|_| format!("Unable to restart PID {:?} for syscall entry wait", pid))?;
            Ok(())
        }
        nix::sys::signal::Signal::SIGTERM => {
            info!("SIGTERM received for PID {:?}", pid);

            // TODO: get exit status
            child.trace_state = ProcessTraceState::Terminated(-1);

            Ok(())
        }
        _ => {
            ptrace::syscall(pid)
                .map_err(|_| format!("Unable to restart PID {:?} for syscall entry wait", pid))?;
            Err(format!("{:?}: unhandled signal {:?}", pid, sig))
        }
    }
}

fn handle_wait_status(
    wait_status: &wait::WaitStatus,
    processes: &mut ProcessList,
    app: &App,
    conf: &mut ProcessConf,
    platform_handler: &impl PlatformHandler,
) -> Result<(), String> {
    match wait_status {
        wait::WaitStatus::Stopped(pid, status) => {
            if !processes.0.contains_key(&pid) {
                trace!("New process (stopped): {:?}", pid);
                processes.0.insert(
                    *pid,
                    ProcessState::new(ProcessTraceState::Stopped, ProcessType::ForkedProcess),
                );
                ptrace::syscall(*pid)
                    .map_err(|_| format!("Unable to start PID {:?} for syscall entry wait", pid))?;
            } else if let Some(mut child) = processes.0.get_mut(&pid) {
                if child.trace_state == ProcessTraceState::Created {
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
                    handle_pid_stop(child, *pid, *status, app, conf, platform_handler)?;
                }
            };
            Ok(())
        }

        wait::WaitStatus::PtraceEvent(pid, sig, ev_type) => {
            if let nix::sys::signal::Signal::SIGTRAP = sig {
            } else {
                warn!(
                    "PtraceEvent received, but signal type is unknown ({:?})",
                    sig
                );
            }

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
                if let Ok(child_pid) = ptrace::getevent(*pid) {
                    let child_pid = Pid::from_raw(child_pid as i32);
                    info!("New child PID: {:?}", child_pid);
                    let child_type = match ev_type {
                        1 => ProcessType::ForkedProcess,
                        2 => ProcessType::VForkedProcess,
                        3 => ProcessType::ClonedThread,
                        _ => ProcessType::ForkedProcess,
                    };
                    processes.0.entry(child_pid)
                        .and_modify(|ch| {
                            if ch.trace_state == ProcessTraceState::Stopped {
                                info!("Changing existing Stopped process {:?} to RunningAwaitSyscall ({:?})...", child_pid, ch);
                                ch.trace_state = ProcessTraceState::RunningAwaitSyscall;
                                ch.process_type = child_type;
                            }
                        })
                        .or_insert_with(|| {
                            info!("Process does not exist, adding as Created...");
                            ProcessState::new(ProcessTraceState::Created, child_type)
                        });
                }
            }

            // Restart PID that sent event (parent of newly-created PID)
            ptrace::syscall(*pid)
                .map_err(|_| format!("Unable to restart PID {:?} for syscall entry wait", pid))?;

            Ok(())
        }

        wait::WaitStatus::Exited(pid, code) => {
            info!("Child process {:?} exited with code {}", pid, code);
            if let Some(mut child) = processes.0.get_mut(&pid) {
                child.trace_state = ProcessTraceState::Terminated(*code as isize);
            }
            Ok(())
        }

        _ => Ok(()),
    }
}

pub fn child_loop(
    app: &App,
    tracee_pid: Pid,
    platform_handler: impl PlatformHandler,
    conf: &mut ProcessConf,
) -> Result<ProcessList, String> {
    let mut processes: ProcessList = ProcessList::new();

    processes.0.insert(
        tracee_pid,
        ProcessState::new(
            ProcessTraceState::RunningAwaitSyscall,
            ProcessType::MainTracee,
        ),
    );

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

    loop {
        // Check "sigint" flag: if set, kill the tracee process and break from the loop
        if sigint.load(Ordering::Relaxed) {
            warn!("SIGINT received, killing tracee process...");
            if let Err(e) = signal::kill(tracee_pid, signal::Signal::SIGTERM) {
                warn!("Unable to send SIGTERM to tracee process: {}", e);
            }
            break;
        }

        // Wait for any child process (-1)
        let wait_status = wait_child(Pid::from_raw(-1 as i32));
        if let Ok(ws) = wait_status {
            if let Err(s) = handle_wait_status(&ws, &mut processes, app, conf, &platform_handler) {
                warn!("{}", s);
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
