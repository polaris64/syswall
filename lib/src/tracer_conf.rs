use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use crate::syscalls::SyscallQuery;
use crate::user_response::UserResponse;

/// Configuration for a single syscall used to make a decision when that syscall is observed in the
/// tracee.
#[derive(Debug, Deserialize, Serialize)]
pub enum SyscallConfig {
    Allowed,
    HardBlocked,
    SoftBlocked,
}

/// Mapping of syscall IDs to `SyscallConfig`
pub type SyscallConfigMap = HashMap<usize, SyscallConfig>;

/// Configuration for the tracer while it is tracing a child process
///
/// Currently contains a `SyscallConfigMap` mapping syscalls with decisions (allowed, blocked,
/// etc.)
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct TracerConf {
    pub syscalls: SyscallConfigMap,
}

impl TracerConf {
    /// Loads the `TracerConf` from a JSON file
    pub fn from_file(filename: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let path = Path::new(filename);
        let mut file = File::open(&path)?;
        let mut ser = String::new();
        file.read_to_string(&mut ser)?;
        serde_json::from_str(ser.as_str()).map_err(|e| e.into())
    }

    /// Sets a `SyscallConfig` for a specific syscall ID
    pub fn add_syscall_conf(&mut self, id: usize, conf: SyscallConfig) {
        *self.syscalls.entry(id).or_insert(SyscallConfig::Allowed) = conf;
    }

    /// Saves the `TracerConf` to a JSON file
    pub fn write_to_file(&self, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
        let ser: String = serde_json::to_string(self)?;
        let path = Path::new(filename);
        let mut file = File::create(&path)?;
        file.write_all(ser.as_bytes()).map_err(|e| e.into())
    }
}

/// Configuration of the runtime environment using the `syswall` library.  Currently contains an
/// optional callback function which accepts a `SyscallQuery` and can optionally return a
/// [`UserResponse`].
///
/// [`UserResponse`]: ../user_response/enum.UserResponse.html
#[derive(Default)]
pub struct RuntimeConf<'a> {
    pub syscall_cb: Option<Box<dyn Fn(SyscallQuery) -> Option<UserResponse> + 'a>>,
}

impl<'a> RuntimeConf<'a> {

    /// Assigns the callback function reference
    pub fn set_syscall_cb(&mut self, cb: Box<dyn Fn(SyscallQuery) -> Option<UserResponse> + 'a>) {
        self.syscall_cb = Some(cb);
    }

}
