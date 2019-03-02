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
    pub state: ProcessFileState,
    pub filename: String,
    pub mode: Option<OFlag>,
    pub flags: Option<OFlag>,
}

impl ProcessFileRec {
    pub fn new(path: &str, flag_bits: isize, mode_bits: isize) -> Self {
        Self {
            state: ProcessFileState::PendingSyscall,
            filename: String::from(path),
            mode: OFlag::from_bits(mode_bits as libc::c_int),
            flags: OFlag::from_bits(flag_bits as libc::c_int),
        }
    }
}
