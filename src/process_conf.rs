use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use serde::{Deserialize, Serialize};
use serde_json;

#[derive(Debug, Deserialize, Serialize)]
pub enum SyscallConfig {
    Allowed,
    HardBlocked,
    SoftBlocked,
}

pub type SyscallConfigMap = HashMap<usize, SyscallConfig>;

#[derive(Debug, Deserialize, Serialize)]
pub struct ProcessConf {
    pub syscalls: SyscallConfigMap,
}

impl ProcessConf {
    pub fn new() -> Self {
        Self {
            syscalls: HashMap::new(),
        }
    }

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
