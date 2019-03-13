use libc;
use log::debug;
use nix::sys::ptrace;
use nix::unistd;

use crate::app::{App, UserResponse};
use crate::process_conf::{ProcessConf, SyscallConfig};
use crate::process_state::ProcessState;

use crate::platforms::PlatformHandler;

#[derive(Debug)]
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
    platform_handler: &impl PlatformHandler,
    pid: unistd::Pid,
    regs: &mut SyscallRegs,
) -> HandleSyscallResult {
    let handled = platform_handler.pre(state, regs, pid);

    if handled {
        syscall_choice(app, config, platform_handler, pid, state.syscall_id, regs)
            .unwrap_or(HandleSyscallResult::Unchanged)
    } else {
        HandleSyscallResult::Unchanged
    }
}

pub fn handle_post_syscall(
    state: &mut ProcessState,
    platform_handler: &impl PlatformHandler,
    pid: unistd::Pid,
    regs: &mut SyscallRegs,
) {
    platform_handler.post(state, regs, pid);
}

fn syscall_choice(
    app: &App,
    config: &mut ProcessConf,
    platform_handler: &impl PlatformHandler,
    pid: unistd::Pid,
    syscall_id: Option<u64>,
    regs: &mut SyscallRegs,
) -> Result<HandleSyscallResult, &'static str> {
    let mut res = HandleSyscallResult::Unchanged;

    match config.syscalls.get(&(syscall_id.unwrap() as usize)) {
        Some(conf) => match conf {
            SyscallConfig::Allowed => {
                debug!(" - Allowed by configuration");
            }
            SyscallConfig::HardBlocked => {
                debug!(" - Hard-blocked by configuration");
                if let Ok(()) = platform_handler.block_syscall(pid, regs) {
                    res = HandleSyscallResult::BlockedHard;
                }
            }
            SyscallConfig::SoftBlocked => {
                debug!(" - Soft-blocked by configuration");
                if let Ok(()) = platform_handler.block_syscall(pid, regs) {
                    res = HandleSyscallResult::BlockedSoft;
                }
            }
        },
        None => match app.get_user_input(UserResponse::AllowOnce)? {
            UserResponse::AllowAllSyscall => {
                config.add_syscall_conf(syscall_id.unwrap() as usize, SyscallConfig::Allowed)
            }
            UserResponse::BlockAllSyscallHard => {
                if let Ok(()) = platform_handler.block_syscall(pid, regs) {
                    res = HandleSyscallResult::BlockedHard;
                }
                config.add_syscall_conf(syscall_id.unwrap() as usize, SyscallConfig::HardBlocked);
            }
            UserResponse::BlockOnceHard => {
                if let Ok(()) = platform_handler.block_syscall(pid, regs) {
                    res = HandleSyscallResult::BlockedHard;
                }
            }
            UserResponse::BlockAllSyscallSoft => {
                if let Ok(()) = platform_handler.block_syscall(pid, regs) {
                    res = HandleSyscallResult::BlockedSoft;
                }
                config.add_syscall_conf(syscall_id.unwrap() as usize, SyscallConfig::SoftBlocked);
            }
            UserResponse::BlockOnceSoft => {
                if let Ok(()) = platform_handler.block_syscall(pid, regs) {
                    res = HandleSyscallResult::BlockedSoft;
                }
            }
            _ => (),
        },
    };

    Ok(res)
}

pub fn update_registers(pid: unistd::Pid, regs: &SyscallRegs) -> Result<(), &'static str> {
    ptrace::setregs(pid, *regs).map_err(|_| "Unable to modify syscall registers")
}
