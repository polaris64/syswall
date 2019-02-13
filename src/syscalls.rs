use std::collections::HashMap;
use libc;
use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::unistd;
use nix::sys::ptrace;

use crate::child_process;
use crate::cli;
use crate::process_state::{ProcessState, ProcessFileState};

pub enum HandleSyscallResult {
    BlockedHard,
    BlockedSoft,
    Unchanged,
}

pub enum SyscallConfig {
    Allowed,
    HardBlocked,
    SoftBlocked,
}

pub type SyscallConfigMap = HashMap<usize, SyscallConfig>;
pub type SyscallRegs = libc::user_regs_struct;

pub fn handle_pre_syscall(
    config:     &mut SyscallConfigMap,
    state:      &mut ProcessState,
    pid:        unistd::Pid,
    syscall_id: u64,
    regs:       &mut SyscallRegs,
) -> HandleSyscallResult {
    let mut res = HandleSyscallResult::Unchanged;

    match syscall_id {
        0 => { // read
            eprintln!("Child process {} will read {} bytes from FD {} into buffer at 0x{:X}", pid, regs.rdx, regs.rdi, regs.rsi);

            eprintln!(" - FD {}: {:?}", regs.rdi, state.file_by_fd(regs.rdi as usize));

            res = syscall_choice(config, pid, syscall_id, regs);
        },
        1 => { // write
            eprintln!("Child process {} will write {} bytes to FD {} from buffer at 0x{:X}", pid, regs.rdx, regs.rdi, regs.rsi);

            eprint!(" - Child wants to write: ");
            eprintln!("{:?}", child_process::get_child_buffer(pid, regs.rsi as usize, regs.rdx as usize));

            res = syscall_choice(config, pid, syscall_id, regs);
        },
        2 => { // open
            eprintln!(
                "Child process {} will open a file with flags {:?} and mode {:?}",
                pid,
                OFlag::from_bits(regs.rsi as libc::c_int),
                OFlag::from_bits(regs.rdx as libc::c_int),
            );

            eprint!("File path: ");
            let filepath = child_process::get_child_buffer_cstr(pid, regs.rdi as usize);
            eprintln!("{:?}", filepath);

            // Add file to state
            state.add_pending_file(&filepath, regs.rsi as isize, regs.rdx as isize);

            res = syscall_choice(config, pid, syscall_id, regs);
        },
        3 => { // close
            eprintln!("Child process {} wants to close FD {}", pid, regs.rdi);
            eprintln!(" - FD {}: {:?}", regs.rdi, state.file_by_fd(regs.rdi as usize));
        },
        257 => { // openat
            eprintln!(
                "Child process {} will open a file with flags {:?} and mode {:?} at dirfd {}",
                pid,
                OFlag::from_bits(regs.rdx as libc::c_int),
                OFlag::from_bits(regs.r10 as libc::c_int),
                regs.rdi,
            );

            eprint!(" - File path: ");
            let filepath = child_process::get_child_buffer_cstr(pid, regs.rsi as usize);
            eprintln!("{:?}", filepath);

            // Add file to state
            state.add_pending_file(&filepath, regs.rdx as isize, regs.r10 as isize);

            res = syscall_choice(config, pid, syscall_id, regs);
        },
        _ => (),
    }

    res
}

pub fn handle_post_syscall(
    pre_result: HandleSyscallResult,
    state:      &mut ProcessState,
    pid:        unistd::Pid,
    syscall_id: u64,
    regs:       &mut SyscallRegs,
) {
    match pre_result {
        HandleSyscallResult::BlockedHard => {
            update_regs_hard_block(pid, regs);
            match syscall_id {
                2 => { // open
                    // Set the pending file open as blocked
                    state.update_pending_file_state(ProcessFileState::OpenBlockedHard);
                },
                257 => { // openat
                    // Set the pending file open as blocked
                    state.update_pending_file_state(ProcessFileState::OpenBlockedHard);
                },
                _ => (),
            }
        },
        HandleSyscallResult::BlockedSoft => {
            match syscall_id {
                0 => { // read
                    // Set return value to number of bytes intended to be read to simulate success
                    regs.rax = regs.rdx;
                    update_registers(pid, regs);
                },
                1 => { // write
                    // Set return value to number of bytes intended to be written to simulate
                    // success
                    regs.rax = regs.rdx;
                    update_registers(pid, regs);
                },
                2 => { // open
                    // TODO: simulate open return
                    regs.rax = 5;
                    update_registers(pid, regs);

                    // Set the pending file open as blocked
                    state.update_pending_file_state(ProcessFileState::OpenBlockedSoft);
                },
                257 => { // openat
                    // TODO: simulate openat return
                    regs.rax = 5;
                    update_registers(pid, regs);

                    // Set the pending file open as blocked
                    state.update_pending_file_state(ProcessFileState::OpenBlockedSoft);
                },
                _ => (),
            }
        },
        HandleSyscallResult::Unchanged => {
            match syscall_id {
                0 => { // read
                    // TODO: update file read bytes in state
                },
                1 => { // write
                    // TODO: update file write bytes in state
                },
                2 => { // open
                    // Set file state according to return value
                    if (regs.rax as isize) < 0 {
                        state.update_pending_file_state(
                            ProcessFileState::CouldNotOpen(Errno::from_i32(-(regs.rax as i32))),
                        );
                    } else {
                        state.update_pending_file_state(
                            ProcessFileState::Opened(regs.rax as usize),
                        );
                    }
                },
                3 => { // close
                    state.update_file_state_by_fd(regs.rdi as usize, ProcessFileState::Closed);
                },
                257 => { // openat
                    // Set file state according to return value
                    if (regs.rax as isize) < 0 {
                        state.update_pending_file_state(
                            ProcessFileState::CouldNotOpen(Errno::from_i32(-(regs.rax as i32))),
                        );
                    } else {
                        state.update_pending_file_state(
                            ProcessFileState::Opened(regs.rax as usize),
                        );
                    }
                },
                _ => (),
            };
        },
    }
}

fn syscall_choice(config: &mut SyscallConfigMap, pid: unistd::Pid, syscall_id: u64, regs: &mut SyscallRegs) -> HandleSyscallResult {
    let mut res = HandleSyscallResult::Unchanged;

    match config.get(&(syscall_id as usize)) {
        Some(conf) => {
            match conf {
                SyscallConfig::Allowed => {
                    eprintln!(" - Allowed by configuration");
                },
                SyscallConfig::HardBlocked => {
                    eprintln!(" - Hard-blocked by configuration");
                    block_syscall(pid, regs);
                    res = HandleSyscallResult::BlockedHard;
                },
                SyscallConfig::SoftBlocked => {
                    eprintln!(" - Soft-blocked by configuration");
                    block_syscall(pid, regs);
                    res = HandleSyscallResult::BlockedSoft;
                },
            }
        },
        None => {
            match cli::get_user_input(cli::UserResponse::AllowOnce) {
                cli::UserResponse::AllowAllSyscall => {
                    *config.entry(syscall_id as usize).or_insert(SyscallConfig::Allowed) = SyscallConfig::Allowed;
                },
                cli::UserResponse::BlockAllSyscallHard => {
                    block_syscall(pid, regs);
                    res = HandleSyscallResult::BlockedHard;
                    *config.entry(syscall_id as usize).or_insert(SyscallConfig::HardBlocked) = SyscallConfig::HardBlocked;
                },
                cli::UserResponse::BlockOnceHard => {
                    block_syscall(pid, regs);
                    res = HandleSyscallResult::BlockedHard;
                },
                cli::UserResponse::BlockAllSyscallSoft => {
                    block_syscall(pid, regs);
                    res = HandleSyscallResult::BlockedSoft;
                    *config.entry(syscall_id as usize).or_insert(SyscallConfig::SoftBlocked) = SyscallConfig::SoftBlocked;
                },
                cli::UserResponse::BlockOnceSoft => {
                    block_syscall(pid, regs);
                    res = HandleSyscallResult::BlockedSoft;
                },
                _ => (),
            }
        }
    }

    res
}

fn update_registers(pid: unistd::Pid, regs: &SyscallRegs) {
    ptrace::setregs(pid, *regs).expect("Unable to modify syscall registers");
}

fn update_regs_hard_block(pid: unistd::Pid, regs: &mut SyscallRegs) {
    regs.rax = (-libc::EPERM) as u64;
    update_registers(pid, regs);
}

fn block_syscall(pid: unistd::Pid, regs: &mut SyscallRegs) {
    regs.orig_rax = std::u64::MAX;
    update_registers(pid, regs);
}
