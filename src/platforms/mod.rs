pub mod linux_x86_64;

use nix::unistd::Pid;

use crate::process_state::ProcessState;
use crate::syscalls::SyscallRegs;

pub trait PlatformHandler {
    fn block_syscall(&self, pid: Pid, regs: &mut SyscallRegs) -> Result<(), &'static str>;
    fn pre(
        &self,
        state: &mut ProcessState,
        regs: &mut SyscallRegs,
        pid: Pid,
    ) -> bool;
    fn post(
        &self,
        state: &mut ProcessState,
        regs: &mut SyscallRegs,
        pid: Pid,
    );
    fn update_regs_hard_block(&self, pid: Pid, regs: &mut SyscallRegs) -> Result<(), &'static str>;
}
