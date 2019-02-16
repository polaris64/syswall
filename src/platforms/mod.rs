pub mod linux_x86_64;

use nix::unistd::Pid;

use crate::process_state::ProcessState;
use crate::syscalls::{HandleSyscallResult, SyscallRegs};

pub trait PlatformHandler {
    fn block_syscall(&self, pid: Pid, regs: &mut SyscallRegs) -> Result<(), &'static str>;
    fn pre(
        &self,
        state: &mut ProcessState,
        regs: &mut SyscallRegs,
        pid: Pid,
        syscall_id: usize,
    ) -> bool;
    fn post(
        &self,
        pre_result: HandleSyscallResult,
        state: &mut ProcessState,
        regs: &mut SyscallRegs,
        pid: Pid,
        syscall_id: usize,
    );
    fn update_regs_hard_block(&self, pid: Pid, regs: &mut SyscallRegs) -> Result<(), &'static str>;
}
