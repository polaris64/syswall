use libc;
use log::{debug, trace};
use nix::sys::ptrace;
use nix::unistd;

use crate::platforms::PlatformHandler;
use crate::process_state::ProcessState;
use crate::tracer_conf::{RuntimeConf, SyscallConfig, TracerConf};
use crate::user_response::UserResponse;

/// A single query caused by a syscall which contains all necessary details required to make a
/// decision
pub struct SyscallQuery<'a> {
    pub configured_choice: Option<&'a SyscallConfig>,
    pub id: usize,
    pub pid: unistd::Pid,
    pub regs: &'a SyscallRegs,
    pub description: String,
}

impl<'a> SyscallQuery<'a> {

    /// Creates a new `SyscallQuery` based on a syscall event
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

/// Result of handling a syscall
#[derive(Debug)]
pub enum HandleSyscallResult {
    BlockedHard,
    BlockedSoft,
    Unchanged,
}

/// Register state during a syscall
pub type SyscallRegs = libc::user_regs_struct;

/// Provides all necessary configuration for the tracer to handle syscalls from a tracee process
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

    /// Called before a syscall is executed in order to obtain a decision and to modify the syscall
    /// before execution as necessary.
    ///
    /// # Arguments
    ///
    ///   - `state`: `ProcessState` of the specific child process triggering the syscall
    ///   - `pid`: child process ID
    ///   - `regs`: CPU registers at the time of syscall invocation
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

    /// Called after a syscall is executed in order to update process states and to modify the
    /// syscall return value that the child process will see if necessary.
    ///
    /// # Arguments
    ///
    ///   - `state`: `ProcessState` of the specific child process triggering the syscall
    ///   - `pid`: child process ID
    ///   - `regs`: CPU registers after syscall invocation
    pub fn handle_post_syscall(
        &self,
        state: &mut ProcessState,
        pid: unistd::Pid,
        regs: &mut SyscallRegs,
    ) {
        self.platform_handler.post(state, regs, pid);
    }

    /// Attempts to obtain a decision from the user for a syscall.  The user's choice is used if
    /// available, otherwise either a configured choice (e.g. "always block") or a default
    /// ("allow") is used.
    ///
    /// # Arguments
    ///
    ///   - `pid`: child process ID
    ///   - `syscall_id`: ID of the syscall being triggered
    ///   - `regs`: CPU registers prior to syscall invocation
    ///   - `description`: a description of this syscall obtained from the current `PlatformHandler`
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

    /// Processes a user's reponse to a syscall
    ///
    /// # Arguments
    ///
    ///   - `choice`: user's decision
    ///   - `syscall_id`: ID of the syscall being triggered
    ///   - `pid`: child process ID
    ///   - `regs`: CPU registers which will be modified according to decision
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

    /// Processes a pre-configured decision for a syscall
    ///
    /// # Arguments
    ///
    ///   - `syscall_conf`: the syscall's configuration
    ///   - `pid`: child process ID
    ///   - `regs`: CPU registers which will be modified according to decision
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

/// Updates the syscall registers for a child process
///
/// # Arguments
///
///   - `pid`: child process ID
///   - `regs`: updated CPU registers to be set
pub fn update_registers(pid: unistd::Pid, regs: &SyscallRegs) -> Result<(), &'static str> {
    ptrace::setregs(pid, *regs).map_err(|_| "Unable to modify syscall registers")
}
