use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use crate::syscalls::SyscallQuery;
use crate::user_response::UserResponse;

#[derive(Debug, Deserialize, Serialize)]
pub enum SyscallConfig {
    Allowed,
    HardBlocked,
    SoftBlocked,
}

pub type SyscallConfigMap = HashMap<usize, SyscallConfig>;

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct TracerConf {
    pub syscalls: SyscallConfigMap,
}

impl TracerConf {
    pub fn from_file(filename: &str) -> Result<Self, Box<std::error::Error>> {
        let path = Path::new(filename);
        let mut file = File::open(&path)?;
        let mut ser = String::new();
        file.read_to_string(&mut ser)?;
        serde_json::from_str(ser.as_str()).map_err(|e| e.into())
    }

    pub fn add_syscall_conf(&mut self, id: usize, conf: SyscallConfig) {
        *self.syscalls.entry(id).or_insert(SyscallConfig::Allowed) = conf;
    }

    pub fn write_to_file(&self, filename: &str) -> Result<(), Box<std::error::Error>> {
        let ser: String = serde_json::to_string(self)?;
        let path = Path::new(filename);
        let mut file = File::create(&path)?;
        file.write_all(ser.as_bytes()).map_err(|e| e.into())
    }
}

#[derive(Default)]
pub struct RuntimeConf<'a> {
    pub syscall_cb: Option<Box<Fn(SyscallQuery) -> Option<UserResponse> + 'a>>,
}

impl<'a> RuntimeConf<'a> {
    pub fn set_syscall_cb(&mut self, cb: Box<Fn(SyscallQuery) -> Option<UserResponse> + 'a>) {
        self.syscall_cb = Some(cb);
    }
}
