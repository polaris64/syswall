use nix::errno::Errno;
use nix::fcntl::OFlag;

#[derive(Debug, PartialEq)]
pub enum ProcessFileState {
    Closed,
    CouldNotOpen(Errno),
    OpenBlockedHard,
    OpenBlockedSoft,
    Opened(usize),
    PendingSyscall,
}

#[derive(Debug)]
pub struct ProcessFileRec {
    pub state:    ProcessFileState,
    pub filename: String,
    pub mode:     Option<OFlag>,
    pub flags:    Option<OFlag>,
}

impl ProcessFileRec {
    pub fn new(path: &str, flag_bits: isize , mode_bits: isize) -> Self {
        Self {
            state:    ProcessFileState::PendingSyscall,
            filename: String::from(path),
            mode:     OFlag::from_bits(mode_bits as libc::c_int),
            flags:    OFlag::from_bits(flag_bits as libc::c_int),
        }
    }
}

#[derive(Debug)]
pub struct ProcessState {
    files: Vec<ProcessFileRec>,
}

impl ProcessState {
    pub fn new() -> Self {
        Self {
            files: Vec::new(),
        }
    }

    pub fn file_by_fd(&mut self, fd: usize) -> Option<&mut ProcessFileRec> {
        self.files.iter_mut().find(|x| x.state == ProcessFileState::Opened(fd))
    }

    pub fn file_by_path(&mut self, path: &str) -> Option<&mut ProcessFileRec> {
        self.files.iter_mut().find(|x| x.filename == path)
    }

    pub fn add_pending_file(&mut self, path: &str, flags: isize, mode: isize) {
        if self.file_by_path(path).is_none() {
            self.files.push(ProcessFileRec::new(path, flags, mode));
        }
    }

    pub fn first_pending_file(&mut self) -> Option<&mut ProcessFileRec> {
        self.files.iter_mut().find(|x| x.state == ProcessFileState::PendingSyscall)
    }

    pub fn update_pending_file_state(&mut self, file_state: ProcessFileState) {
        if let Some(f) = self.first_pending_file() {
            f.state = file_state;
        }
    }

    pub fn update_file_state_by_fd(&mut self, fd: usize, file_state: ProcessFileState) {
        if let Some(f) = self.file_by_fd(fd) {
            f.state = file_state;
        }
    }

    pub fn report_blocked_files(&self, join: &str, prefix: &str) -> String {
        self.files.iter()
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
        self.files.iter()
            .filter(|x| match x.state {
                ProcessFileState::Opened(_) | ProcessFileState::Closed => true,
                _ => false,
            })
            .map(|x| String::from(prefix) + &x.filename.clone())
            .collect::<Vec<String>>()
            .as_slice()
            .join(join)
    }

    pub fn report(&self) -> String {
        let blocked_files = self.report_blocked_files("\n", "  - ");
        let opened_files  = self.report_opened_files("\n", "  - ");
        let mut res = String::new();
        if !blocked_files.is_empty() {
            res += &format!("\nThe process was blocked from opening the following files: -\n{}", blocked_files);
        }
        if !opened_files.is_empty() {
            res += &format!("\nThe process opened the following files: -\n{}", opened_files);
        }
        res
    }
}
