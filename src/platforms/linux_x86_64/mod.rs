mod sockets;

use log::{error, info, trace};
use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::unistd::Pid;

use crate::child_process;
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

impl crate::platforms::PlatformHandler for Handler {
    fn block_syscall(&self, pid: Pid, regs: &mut SyscallRegs) -> Result<(), &'static str> {
        regs.orig_rax = std::u64::MAX;
        update_registers(pid, regs)
    }

    fn pre(
        &self,
        state: &mut ProcessState,
        regs: &mut SyscallRegs,
        pid: Pid,
        syscall_id: usize,
    ) -> bool {
        match syscall_id {
            // read
            0 => {
                info!(
                    "Child process {} will read {} bytes from FD {} into buffer at 0x{:X}",
                    pid, regs.rdx, regs.rdi, regs.rsi
                );
                info!(
                    " - FD {}: {:?}",
                    regs.rdi,
                    state.file_by_fd(regs.rdi as usize)
                );
                true
            }

            // write
            1 => {
                info!(
                    "Child process {} will write {} bytes to FD {} from buffer at 0x{:X}",
                    pid, regs.rdx, regs.rdi, regs.rsi
                );
                match child_process::get_child_buffer(pid, regs.rsi as usize, regs.rdx as usize) {
                    Ok(buf) => info!(" - Child wants to write: {:?}", String::from(buf)),
                    Err(e) => error!(" - Unable to read from child process buffer: {}", e),
                };
                true
            }

            // open
            2 => {
                info!(
                    "Child process {} will open a file with flags {:?} and mode {:?}",
                    pid,
                    OFlag::from_bits(regs.rsi as libc::c_int),
                    OFlag::from_bits(regs.rdx as libc::c_int),
                );
                match child_process::get_child_buffer_cstr(pid, regs.rdi as usize) {
                    Ok(filepath) => {
                        info!(" - File path: {:?}", filepath);

                        // Add file to state
                        state.add_pending_file(&filepath, regs.rsi as isize, regs.rdx as isize);
                    }
                    Err(e) => error!(" - Could not get file path: {}", e),
                };
                true
            }

            // close
            3 => {
                info!("Child process {} wants to close FD {}", pid, regs.rdi);
                {
                    let file = state.file_by_fd(regs.rdi as usize);
                    if file.is_some() {
                        info!(" - FD {}: {:?}", regs.rdi, file);
                    }
                }
                {
                    let sock = state.socket_by_fd(regs.rdi as usize);
                    if sock.is_some() {
                        info!(" - FD {}: {:?}", regs.rdi, sock);
                    }
                }
                true
            }

            // socket
            41 => {
                sockets::handle_socket_pre(state, regs, pid);
                true
            }

            // connect
            42 => {
                sockets::handle_connect_pre(state, regs, pid);
                true
            }

            // openat
            257 => {
                info!(
                    "Child process {} will open a file with flags {:?} and mode {:?} at dirfd {}",
                    pid,
                    OFlag::from_bits(regs.rdx as libc::c_int),
                    OFlag::from_bits(regs.r10 as libc::c_int),
                    regs.rdi,
                );
                match child_process::get_child_buffer_cstr(pid, regs.rsi as usize) {
                    Ok(filepath) => {
                        info!(" - File path: {:?}", filepath);

                        // Add file to state
                        state.add_pending_file(&filepath, regs.rdx as isize, regs.r10 as isize);
                    }
                    Err(e) => error!(" - Could not get file path: {}", e),
                };
                true
            }
            _ => {
                trace!(
                    "Unhandled syscall {} ({:X}, {:X}, {:X}, {:X}, {:X}, {:X})",
                    syscall_id,
                    regs.rdi,
                    regs.rsi,
                    regs.rdx,
                    regs.r10,
                    regs.r8,
                    regs.r9
                );
                false
            },
        }
    }

    fn post(
        &self,
        pre_result: HandleSyscallResult,
        state: &mut ProcessState,
        regs: &mut SyscallRegs,
        pid: Pid,
        syscall_id: usize,
    ) {
        match pre_result {
            HandleSyscallResult::BlockedHard => {
                if let Ok(()) = self.update_regs_hard_block(pid, regs) {
                    match syscall_id {
                        // open
                        2 => {
                            // Set the pending file open as blocked
                            state.update_pending_file_state(ProcessFileState::OpenBlockedHard);
                        }

                        // socket
                        41 => {
                            state.update_pending_socket_state(ProcessSocketState::CreateBlockedHard);
                        }

                        // connect
                        42 => {
                            if let Some(ref mut sock) = state.socket_by_fd(regs.rdi as usize) {
                                sock.connection_state = SocketConnectionState::ConnectBlockedHard;
                            }
                        }

                        // openat
                        257 => {
                            // Set the pending file open as blocked
                            state.update_pending_file_state(ProcessFileState::OpenBlockedHard);
                        }
                        _ => (),
                    };
                };
            }
            HandleSyscallResult::BlockedSoft => {
                match syscall_id {
                    // read
                    0 => {
                        // Set return value to number of bytes intended to be read to simulate success
                        regs.rax = regs.rdx;
                        update_registers(pid, regs).unwrap_or_else(|e| error!("{}", e));
                    }

                    // write
                    1 => {
                        // Set return value to number of bytes intended to be written to simulate
                        // success
                        regs.rax = regs.rdx;
                        update_registers(pid, regs).unwrap_or_else(|e| error!("{}", e));
                    }

                    // open
                    2 => {
                        // TODO: simulate open return
                        regs.rax = 5;
                        update_registers(pid, regs).unwrap_or_else(|e| error!("{}", e));

                        // Set the pending file open as blocked
                        state.update_pending_file_state(ProcessFileState::OpenBlockedSoft);
                    }

                    // socket
                    41 => {
                        // TODO: simulate socket return
                        regs.rax = 5;
                        update_registers(pid, regs).unwrap_or_else(|e| error!("{}", e));

                        state.update_pending_socket_state(ProcessSocketState::CreateBlockedSoft);
                    }

                    // connect
                    42 => {
                        // TODO: handle connect error
                        if let Some(ref mut sock) = state.socket_by_fd(regs.rdi as usize) {
                            sock.connection_state = SocketConnectionState::ConnectBlockedSoft;
                        }
                    }

                    // openat
                    257 => {
                        // TODO: simulate openat return
                        regs.rax = 5;
                        update_registers(pid, regs).unwrap_or_else(|e| error!("{}", e));

                        // Set the pending file open as blocked
                        state.update_pending_file_state(ProcessFileState::OpenBlockedSoft);
                    }
                    _ => (),
                }
            }
            HandleSyscallResult::Unchanged => {
                match syscall_id {
                    // read
                    0 => {
                        // TODO: update file read bytes in state
                    }

                    // write
                    1 => {
                        // TODO: update file write bytes in state
                    }

                    // open
                    2 => {
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
                    3 => {
                        state.update_file_state_by_fd(regs.rdi as usize, ProcessFileState::Closed);
                        state.update_socket_state_by_fd(regs.rdi as usize, ProcessSocketState::Closed);
                    }

                    // socket
                    41 => {
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
                    42 => {
                        if let Some(ref mut sock) = state.socket_by_fd(regs.rdi as usize) {
                            sock.connection_state = SocketConnectionState::Connected;
                        }
                    }

                    // openat
                    257 => {
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
        }
    }

    fn update_regs_hard_block(&self, pid: Pid, regs: &mut SyscallRegs) -> Result<(), &'static str> {
        regs.rax = (-libc::EPERM) as u64;
        update_registers(pid, regs)
    }
}
