use libc;
use log::{debug, error, info};
use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::sys::ptrace;
use nix::unistd;

use crate::app::{App, UserResponse};
use crate::child_process;
use crate::process_conf::{ProcessConf, SyscallConfig};
use crate::process_state::{ProcessFileState, ProcessState};

pub enum HandleSyscallResult {
    BlockedHard,
    BlockedSoft,
    Unchanged,
}

pub type SyscallRegs = libc::user_regs_struct;

pub fn handle_pre_syscall(
    app: &App,
    config: &mut ProcessConf,
    state: &mut ProcessState,
    pid: unistd::Pid,
    syscall_id: u64,
    regs: &mut SyscallRegs,
) -> HandleSyscallResult {
    let mut res = HandleSyscallResult::Unchanged;

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

            res = syscall_choice(app, config, pid, syscall_id, regs)
                .unwrap_or(HandleSyscallResult::Unchanged);
        }

        // write
        1 => {
            info!(
                "Child process {} will write {} bytes to FD {} from buffer at 0x{:X}",
                pid, regs.rdx, regs.rdi, regs.rsi
            );

            match child_process::get_child_buffer(pid, regs.rsi as usize, regs.rdx as usize) {
                Ok(buf) => info!(" - Child wants to write: {:?}", buf),
                Err(e) => error!(" - Unable to read from child process buffer: {}", e),
            };

            res = syscall_choice(app, config, pid, syscall_id, regs)
                .unwrap_or(HandleSyscallResult::Unchanged);
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

            res = syscall_choice(app, config, pid, syscall_id, regs)
                .unwrap_or(HandleSyscallResult::Unchanged);
        }

        // close
        3 => {
            info!("Child process {} wants to close FD {}", pid, regs.rdi);
            info!(
                " - FD {}: {:?}",
                regs.rdi,
                state.file_by_fd(regs.rdi as usize)
            );
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

            res = syscall_choice(app, config, pid, syscall_id, regs)
                .unwrap_or(HandleSyscallResult::Unchanged);
        }
        _ => (),
    }

    res
}

pub fn handle_post_syscall(
    pre_result: HandleSyscallResult,
    state: &mut ProcessState,
    pid: unistd::Pid,
    syscall_id: u64,
    regs: &mut SyscallRegs,
) {
    match pre_result {
        HandleSyscallResult::BlockedHard => {
            if let Ok(()) = update_regs_hard_block(pid, regs) {
                match syscall_id {
                    // open
                    2 => {
                        // Set the pending file open as blocked
                        state.update_pending_file_state(ProcessFileState::OpenBlockedHard);
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
                        state
                            .update_pending_file_state(ProcessFileState::Opened(regs.rax as usize));
                    }
                }

                // close
                3 => {
                    state.update_file_state_by_fd(regs.rdi as usize, ProcessFileState::Closed);
                }

                // openat
                257 => {
                    // Set file state according to return value
                    if (regs.rax as isize) < 0 {
                        state.update_pending_file_state(ProcessFileState::CouldNotOpen(
                            Errno::from_i32(-(regs.rax as i32)),
                        ));
                    } else {
                        state
                            .update_pending_file_state(ProcessFileState::Opened(regs.rax as usize));
                    }
                }
                _ => (),
            };
        }
    }
}

fn syscall_choice(
    app: &App,
    config: &mut ProcessConf,
    pid: unistd::Pid,
    syscall_id: u64,
    regs: &mut SyscallRegs,
) -> Result<HandleSyscallResult, &'static str> {
    let mut res = HandleSyscallResult::Unchanged;

    match config.syscalls.get(&(syscall_id as usize)) {
        Some(conf) => match conf {
            SyscallConfig::Allowed => {
                debug!(" - Allowed by configuration");
            }
            SyscallConfig::HardBlocked => {
                debug!(" - Hard-blocked by configuration");
                if let Ok(()) = block_syscall(pid, regs) {
                    res = HandleSyscallResult::BlockedHard;
                }
            }
            SyscallConfig::SoftBlocked => {
                debug!(" - Soft-blocked by configuration");
                if let Ok(()) = block_syscall(pid, regs) {
                    res = HandleSyscallResult::BlockedSoft;
                }
            }
        },
        None => match app.get_user_input(UserResponse::AllowOnce)? {
            UserResponse::AllowAllSyscall => {
                config.add_syscall_conf(syscall_id as usize, SyscallConfig::Allowed)
            }
            UserResponse::BlockAllSyscallHard => {
                if let Ok(()) = block_syscall(pid, regs) {
                    res = HandleSyscallResult::BlockedHard;
                }
                config.add_syscall_conf(syscall_id as usize, SyscallConfig::HardBlocked);
            }
            UserResponse::BlockOnceHard => {
                if let Ok(()) = block_syscall(pid, regs) {
                    res = HandleSyscallResult::BlockedHard;
                }
            }
            UserResponse::BlockAllSyscallSoft => {
                if let Ok(()) = block_syscall(pid, regs) {
                    res = HandleSyscallResult::BlockedSoft;
                }
                config.add_syscall_conf(syscall_id as usize, SyscallConfig::SoftBlocked);
            }
            UserResponse::BlockOnceSoft => {
                if let Ok(()) = block_syscall(pid, regs) {
                    res = HandleSyscallResult::BlockedSoft;
                }
            }
            _ => (),
        },
    }

    Ok(res)
}

fn update_registers(pid: unistd::Pid, regs: &SyscallRegs) -> Result<(), &'static str> {
    ptrace::setregs(pid, *regs).map_err(|_| "Unable to modify syscall registers")
}

fn update_regs_hard_block(pid: unistd::Pid, regs: &mut SyscallRegs) -> Result<(), &'static str> {
    regs.rax = (-libc::EPERM) as u64;
    update_registers(pid, regs)
}

fn block_syscall(pid: unistd::Pid, regs: &mut SyscallRegs) -> Result<(), &'static str> {
    regs.orig_rax = std::u64::MAX;
    update_registers(pid, regs)
}
