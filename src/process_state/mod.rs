pub mod files;
pub mod sockets;

use files::{ProcessFileRec, ProcessFileState};
use sockets::{ProcessSocketRec, ProcessSocketState};

#[derive(Debug)]
pub struct ProcessState {
    files: Vec<ProcessFileRec>,
    sockets: Vec<ProcessSocketRec>,
}

impl ProcessState {
    pub fn new() -> Self {
        Self {
            files: Vec::new(),
            sockets: Vec::new(),
        }
    }

    pub fn file_by_fd(&mut self, fd: usize) -> Option<&mut ProcessFileRec> {
        self.files
            .iter_mut()
            .find(|x| x.state == ProcessFileState::Opened(fd))
    }

    pub fn socket_by_fd(&mut self, fd: usize) -> Option<&mut ProcessSocketRec> {
        self.sockets
            .iter_mut()
            .find(|x| x.state == ProcessSocketState::Created(fd))
    }

    pub fn file_by_path(&mut self, path: &str) -> Option<&mut ProcessFileRec> {
        self.files.iter_mut().find(|x| x.filename == path)
    }

    pub fn add_pending_file(&mut self, path: &str, flags: isize, mode: isize) {
        if self.file_by_path(path).is_none() {
            self.files.push(ProcessFileRec::new(path, flags, mode));
        }
    }

    pub fn add_pending_socket(&mut self, af: isize, sock_type: isize, sock_proto: isize) {
        let v = ProcessSocketRec::new(af, sock_type, sock_proto);
        self.sockets.push(v);
    }

    pub fn first_pending_file(&mut self) -> Option<&mut ProcessFileRec> {
        self.files
            .iter_mut()
            .find(|x| x.state == ProcessFileState::PendingSyscall)
    }

    pub fn first_pending_socket(&mut self) -> Option<&mut ProcessSocketRec> {
        self.sockets
            .iter_mut()
            .find(|x| x.state == ProcessSocketState::PendingSyscall)
    }

    pub fn update_pending_file_state(&mut self, file_state: ProcessFileState) {
        if let Some(f) = self.first_pending_file() {
            f.state = file_state;
        }
    }

    pub fn update_pending_socket_state(&mut self, sock_state: ProcessSocketState) {
        if let Some(s) = self.first_pending_socket() {
            s.state = sock_state;
        }
    }

    pub fn update_file_state_by_fd(&mut self, fd: usize, state: ProcessFileState) {
        if let Some(f) = self.file_by_fd(fd) {
            f.state = state;
        }
    }

    pub fn update_socket_state_by_fd(&mut self, fd: usize, state: ProcessSocketState) {
        if let Some(s) = self.socket_by_fd(fd) {
            s.state = state;
        }
    }

    pub fn report_blocked_files(&self, join: &str, prefix: &str) -> String {
        self.files
            .iter()
            .filter(|x| match x.state {
                ProcessFileState::OpenBlockedHard | ProcessFileState::OpenBlockedSoft => true,
                _ => false,
            })
            .map(|x| String::from(prefix) + &x.filename.clone())
            .collect::<Vec<String>>()
            .as_slice()
            .join(join)
    }

    pub fn report_opened_files(&self, join: &str, prefix: &str) -> String {
        self.files
            .iter()
            .filter(|x| match x.state {
                ProcessFileState::Opened(_) | ProcessFileState::Closed => true,
                _ => false,
            })
            .map(|x| String::from(prefix) + &x.filename.clone())
            .collect::<Vec<String>>()
            .as_slice()
            .join(join)
    }

    pub fn report_sockets(&self, join: &str, prefix: &str) -> String {
        self.sockets
            .iter()
            .map(|x| String::from(prefix) + &format!("{}", &x))
            .collect::<Vec<String>>()
            .as_slice()
            .join(join)
    }

    pub fn report(&self) -> String {
        let blocked_files = self.report_blocked_files("\n", "  - ");
        let opened_files = self.report_opened_files("\n", "  - ");
        let sockets = self.report_sockets("\n", "  - ");
        let mut res = String::new();
        if !blocked_files.is_empty() {
            res += &format!(
                "\nThe process was blocked from opening the following files: -\n{}",
                blocked_files
            );
        }
        if !opened_files.is_empty() {
            res += &format!(
                "\nThe process opened the following files: -\n{}",
                opened_files
            );
        }
        if !sockets.is_empty() {
            res += &format!(
                "\nThe process created the following sockets: -\n{}",
                sockets
            );
        }
        res
    }
}
