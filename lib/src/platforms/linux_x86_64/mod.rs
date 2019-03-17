mod sockets;

use log::{error, trace};
use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::unistd::Pid;

use crate::child_process;
use crate::platforms::{PlatformHandler, SyscallEntryResult};
use crate::process_state::ProcessState;
use crate::process_state::files::ProcessFileState;
use crate::process_state::sockets::{ProcessSocketState, SocketConnectionState};
use crate::syscalls::{update_registers, HandleSyscallResult, SyscallRegs};

pub struct Handler;

impl Handler {
    pub fn new() -> Self {
        Self
    }
}

impl PlatformHandler for Handler {
    fn block_syscall(&self, pid: Pid, regs: &mut SyscallRegs) -> Result<(), &'static str> {
        regs.orig_rax = std::u64::MAX;
        update_registers(pid, regs)
    }

    fn pre(
        &self,
        state: &mut ProcessState,
        regs: &mut SyscallRegs,
        pid: Pid,
    ) -> SyscallEntryResult {
        match state.syscall_id {
            // read
            Some(0) => {
                SyscallEntryResult::new(
                    true, 
                    format!(
                        "Child process {} will read {} bytes from FD {} into buffer at 0x{:X}\n - File: {:?}",
                        pid, regs.rdx, regs.rdi, regs.rsi, state.file_by_fd(regs.rdi as usize)
                    ),
                )
            }

            // write
            Some(1) => {
                SyscallEntryResult::new(
                    true,
                    format!(
                        "Child process {} will write {} bytes to FD {} from buffer at 0x{:X}\n{}",
                        pid, regs.rdx, regs.rdi, regs.rsi,
                        match child_process::get_child_buffer(pid, regs.rsi as usize, regs.rdx as usize) {
                            Ok(buf) => format!(" - To write: {:?}", String::from(buf)),
                            Err(e) => format!(" - Unable to read from child process buffer: {}", e),
                        },
                    ),
                )
            }

            // open
            Some(2) => {
                let mut desc = format!(
                    "Child process {} will open a file with flags {:?} and mode {:?}",
                    pid,
                    OFlag::from_bits(regs.rsi as libc::c_int),
                    OFlag::from_bits(regs.rdx as libc::c_int),
                );
                match child_process::get_child_buffer_cstr(pid, regs.rdi as usize) {
                    Ok(filepath) => {
                        desc = format!("{}\n{}", desc, format!(" - File path: {:?}", filepath));

                        // Add file to state
                        state.add_pending_file(&filepath, regs.rsi as isize, regs.rdx as isize);
                    }
                    Err(e) => {
                        desc = format!("{}\n{}", desc, format!(" - Could not get file path: {}", e));
                    }
                };
                SyscallEntryResult::new(true, desc)
            }

            // close
            Some(3) => {
                let mut desc = format!("Child process {} wants to close FD {}", pid, regs.rdi);
                {
                    let file = state.file_by_fd(regs.rdi as usize);
                    if file.is_some() {
                        desc = format!("{}\n{}", desc, format!(" - File: {:?}", file));
                    }
                }
                {
                    let sock = state.socket_by_fd(regs.rdi as usize);
                    if sock.is_some() {
                        desc = format!("{}\n{}", desc, format!(" - Socket: {:?}", sock));
                    }
                }
                SyscallEntryResult::new(true, desc)
            }

            // socket
            Some(41) => {
                SyscallEntryResult::new(true, sockets::handle_socket_pre(state, regs, pid))
            }

            // connect
            Some(42) => {
                SyscallEntryResult::new(true, sockets::handle_connect_pre(state, regs, pid))
            }

            // openat
            Some(257) => {
                let mut desc = format!(
                    "Child process {} will open a file with flags {:?} and mode {:?} at dirfd {}",
                    pid,
                    OFlag::from_bits(regs.rdx as libc::c_int),
                    OFlag::from_bits(regs.r10 as libc::c_int),
                    regs.rdi,
                );
                match child_process::get_child_buffer_cstr(pid, regs.rsi as usize) {
                    Ok(filepath) => {
                        desc = format!("{}\n{}", desc, format!(" - File path: {:?}", filepath));

                        // Add file to state
                        state.add_pending_file(&filepath, regs.rdx as isize, regs.r10 as isize);
                    }
                    Err(e) => {
                        desc = format!("{}\n{}", desc, format!(" - Could not get file path: {}", e));
                    }
                };
                SyscallEntryResult::new(true, desc)
            }
            _ => {
                SyscallEntryResult::new(
                    false, 
                    format!(
                        "Unhandled syscall {:?} ({:X}, {:X}, {:X}, {:X}, {:X}, {:X})",
                        state.syscall_id,
                        regs.rdi,
                        regs.rsi,
                        regs.rdx,
                        regs.r10,
                        regs.r8,
                        regs.r9
                    ),
                )
            },
        }
    }

    fn post(
        &self,
        state: &mut ProcessState,
        regs: &mut SyscallRegs,
        pid: Pid,
    ) {
        match state.handler_res {
            Some(HandleSyscallResult::BlockedHard) => {
                if let Ok(()) = self.update_regs_hard_block(pid, regs) {
                    match state.syscall_id {
                        // open
                        Some(2) => {
                            // Set the pending file open as blocked
                            state.update_pending_file_state(ProcessFileState::OpenBlockedHard);
                        }

                        // socket
                        Some(41) => {
                            state.update_pending_socket_state(ProcessSocketState::CreateBlockedHard);
                        }

                        // connect
                        Some(42) => {
                            if let Some(ref mut sock) = state.socket_by_fd(regs.rdi as usize) {
                                sock.connection_state = SocketConnectionState::ConnectBlockedHard;
                            }
                        }

                        // openat
                        Some(257) => {
                            // Set the pending file open as blocked
                            state.update_pending_file_state(ProcessFileState::OpenBlockedHard);
                        }
                        _ => (),
                    };
                };
            }
            Some(HandleSyscallResult::BlockedSoft) => {
                match state.syscall_id {
                    // read
                    Some(0) => {
                        // Set return value to number of bytes intended to be read to simulate success
                        regs.rax = regs.rdx;
                        update_registers(pid, regs).unwrap_or_else(|e| error!("{}", e));
                    }

                    // write
                    Some(1) => {
                        // Set return value to number of bytes intended to be written to simulate
                        // success
                        regs.rax = regs.rdx;
                        update_registers(pid, regs).unwrap_or_else(|e| error!("{}", e));
                    }

                    // open
                    Some(2) => {
                        // TODO: simulate open return
                        regs.rax = 5;
                        update_registers(pid, regs).unwrap_or_else(|e| error!("{}", e));

                        // Set the pending file open as blocked
                        state.update_pending_file_state(ProcessFileState::OpenBlockedSoft);
                    }

                    // socket
                    Some(41) => {
                        // TODO: simulate socket return
                        regs.rax = 5;
                        update_registers(pid, regs).unwrap_or_else(|e| error!("{}", e));

                        state.update_pending_socket_state(ProcessSocketState::CreateBlockedSoft);
                    }

                    // connect
                    Some(42) => {
                        // TODO: simulate connect return
                        if let Some(ref mut sock) = state.socket_by_fd(regs.rdi as usize) {
                            sock.connection_state = SocketConnectionState::ConnectBlockedSoft;
                        }
                    }

                    // openat
                    Some(257) => {
                        // TODO: simulate openat return
                        regs.rax = 5;
                        update_registers(pid, regs).unwrap_or_else(|e| error!("{}", e));

                        // Set the pending file open as blocked
                        state.update_pending_file_state(ProcessFileState::OpenBlockedSoft);
                    }
                    _ => (),
                }
            }
            Some(HandleSyscallResult::Unchanged) => {
                match state.syscall_id {
                    // read
                    Some(0) => {
                        // TODO: update file read bytes in state
                    }

                    // write
                    Some(1) => {
                        // TODO: update file write bytes in state
                    }

                    // open
                    Some(2) => {
                        // Set file state according to return value
                        if (regs.rax as isize) < 0 {
                            state.update_pending_file_state(ProcessFileState::CouldNotOpen(
                                Errno::from_i32(-(regs.rax as i32)),
                            ));
                        } else {
                            state.update_pending_file_state(ProcessFileState::Opened(
                                regs.rax as usize,
                            ));
                        }
                    }

                    // close
                    Some(3) => {
                        state.update_file_state_by_fd(regs.rdi as usize, ProcessFileState::Closed);
                        state.update_socket_state_by_fd(regs.rdi as usize, ProcessSocketState::Closed);
                    }

                    // socket
                    Some(41) => {
                        // Set socket state according to return value
                        if (regs.rax as isize) < 0 {
                            state.update_pending_socket_state(ProcessSocketState::CouldNotCreate(
                                Errno::from_i32(-(regs.rax as i32)),
                            ));
                        } else {
                            state.update_pending_socket_state(ProcessSocketState::Created(
                                regs.rax as usize,
                            ));
                        }
                    }

                    // connect
                    Some(42) => {
                        if let Some(ref mut sock) = state.socket_by_fd(regs.rdi as usize) {
                            if (regs.rax as isize) < 0 {
                                sock.connection_state = SocketConnectionState::ConnectError(
                                    Errno::from_i32(-(regs.rax as i32)),
                                );
                            } else {
                                sock.connection_state = SocketConnectionState::Connected;
                            }
                        }
                    }

                    // openat
                    Some(257) => {
                        // Set file state according to return value
                        if (regs.rax as isize) < 0 {
                            state.update_pending_file_state(ProcessFileState::CouldNotOpen(
                                Errno::from_i32(-(regs.rax as i32)),
                            ));
                        } else {
                            state.update_pending_file_state(ProcessFileState::Opened(
                                regs.rax as usize,
                            ));
                        }
                    }
                    _ => {
                        trace!("Unhandled syscall result: {:X}", regs.rax);
                    },
                };
            }
            _ => {},
        }
    }

    fn update_regs_hard_block(&self, pid: Pid, regs: &mut SyscallRegs) -> Result<(), &'static str> {
        regs.rax = (-libc::EPERM) as u64;
        update_registers(pid, regs)
    }
}
