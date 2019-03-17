use libc;
use log::{debug, trace};
use nix::sys::ptrace;
use nix::unistd;

use crate::platforms::PlatformHandler;
use crate::process_state::ProcessState;
use crate::tracer_conf::{RuntimeConf, SyscallConfig, TracerConf};
use crate::user_response::UserResponse;

pub struct SyscallQuery<'a> {
    pub configured_choice: Option<&'a SyscallConfig>,
    pub id: usize,
    pub pid: unistd::Pid,
    pub regs: &'a SyscallRegs,
    pub description: String,
}

impl<'a> SyscallQuery<'a> {
    pub fn new(
        configured_choice: Option<&'a SyscallConfig>,
        id: usize,
        pid: unistd::Pid,
        regs: &'a SyscallRegs,
        description: String,
    ) -> Self {
        Self {
            configured_choice,
            id,
            pid,
            regs,
            description,
        }
    }
}

#[derive(Debug)]
pub enum HandleSyscallResult {
    BlockedHard,
    BlockedSoft,
    Unchanged,
}

pub type SyscallRegs = libc::user_regs_struct;

pub struct SyscallHandler<'a> {
    config: &'a mut TracerConf,
    runtime_conf: &'a RuntimeConf<'a>,
    platform_handler: Box<PlatformHandler>,
}

impl<'a> SyscallHandler<'a> {

    pub fn new(config: &'a mut TracerConf, runtime_conf: &'a RuntimeConf<'a>, platform_handler: Box<PlatformHandler>) -> Self {
        Self {
            config,
            runtime_conf,
            platform_handler,
        }
    }

    pub fn handle_pre_syscall(
        &mut self,
        state: &mut ProcessState,
        pid: unistd::Pid,
        regs: &mut SyscallRegs,
    ) -> HandleSyscallResult {
        let entry_res = self.platform_handler.pre(state, regs, pid);

        if entry_res.handled {
            self.syscall_choice(
                pid,
                state.syscall_id,
                regs,
                entry_res.description,
            )
        } else {
            trace!("{}", entry_res.description);
            HandleSyscallResult::Unchanged
        }
    }

    pub fn handle_post_syscall(
        &self,
        state: &mut ProcessState,
        pid: unistd::Pid,
        regs: &mut SyscallRegs,
    ) {
        self.platform_handler.post(state, regs, pid);
    }

    fn syscall_choice(
        &mut self,
        pid: unistd::Pid,
        syscall_id: Option<u64>,
        regs: &mut SyscallRegs,
        description: String,
    ) -> HandleSyscallResult {

        // Get optional existing decision from configuration
        let conf_choice = self.config.syscalls.get(&(syscall_id.unwrap() as usize));

        match self.runtime_conf.syscall_cb {

            // A decision callback exists, so call it to allow for an optional change in decision
            Some(ref cb) => {
                let query = SyscallQuery::new(
                    conf_choice,
                    syscall_id.unwrap() as usize,
                    pid,
                    regs,
                    description,
                );

                // Execute callback and get optional choice
                match cb(query) {
                    Some(choice) => {
                        self.handle_user_response(
                            choice,
                            syscall_id.unwrap(),
                            pid,
                            regs,
                        )
                    }
                    None => {
                        self.handle_config_choice(
                            conf_choice,
                            pid,
                            regs,
                        )
                    }
                }
            }

            // No decision callback exists, so handle the syscall using default or configured decision
            None => {
                self.handle_config_choice(
                    conf_choice,
                    pid,
                    regs,
                )
            }
        }
    }

    fn handle_user_response(
        &mut self,
        choice: UserResponse,
        syscall_id: u64,
        pid: unistd::Pid,
        regs: &mut SyscallRegs,
    ) -> HandleSyscallResult {
        match choice {
            UserResponse::AllowAllSyscall => {
                self.config.add_syscall_conf(syscall_id as usize, SyscallConfig::Allowed);
                HandleSyscallResult::Unchanged
            }
            UserResponse::BlockAllSyscallHard => {
                self.config.add_syscall_conf(syscall_id as usize, SyscallConfig::HardBlocked);
                if let Ok(()) = self.platform_handler.block_syscall(pid, regs) {
                    HandleSyscallResult::BlockedHard
                } else {
                    HandleSyscallResult::Unchanged
                }
            }
            UserResponse::BlockOnceHard => {
                if let Ok(()) = self.platform_handler.block_syscall(pid, regs) {
                    HandleSyscallResult::BlockedHard
                } else {
                    HandleSyscallResult::Unchanged
                }
            }
            UserResponse::BlockAllSyscallSoft => {
                self.config.add_syscall_conf(syscall_id as usize, SyscallConfig::SoftBlocked);
                if let Ok(()) = self.platform_handler.block_syscall(pid, regs) {
                    HandleSyscallResult::BlockedSoft
                } else {
                    HandleSyscallResult::Unchanged
                }
            }
            UserResponse::BlockOnceSoft => {
                if let Ok(()) = self.platform_handler.block_syscall(pid, regs) {
                    HandleSyscallResult::BlockedSoft
                } else {
                    HandleSyscallResult::Unchanged
                }
            }
            _ => HandleSyscallResult::Unchanged
        }
    }

    fn handle_config_choice(
        &self,
        syscall_conf: Option<&SyscallConfig>,
        pid: unistd::Pid,
        regs: &mut SyscallRegs,
    ) -> HandleSyscallResult {
        match syscall_conf {
            Some(conf) => {
                match conf {
                    SyscallConfig::Allowed => {
                        debug!(" - Allowed by configuration");
                        HandleSyscallResult::Unchanged
                    }
                    SyscallConfig::HardBlocked => {
                        debug!(" - Hard-blocked by configuration");
                        if let Ok(()) = self.platform_handler.block_syscall(pid, regs) {
                            HandleSyscallResult::BlockedHard
                        } else {
                            HandleSyscallResult::Unchanged
                        }
                    }
                    SyscallConfig::SoftBlocked => {
                        debug!(" - Soft-blocked by configuration");
                        if let Ok(()) = self.platform_handler.block_syscall(pid, regs) {
                            HandleSyscallResult::BlockedSoft
                        } else {
                            HandleSyscallResult::Unchanged
                        }
                    }
                }
            }
            None => HandleSyscallResult::Unchanged,
        }
    }
}

pub fn update_registers(pid: unistd::Pid, regs: &SyscallRegs) -> Result<(), &'static str> {
    ptrace::setregs(pid, *regs).map_err(|_| "Unable to modify syscall registers")
}
