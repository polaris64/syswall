pub enum UserResponse {
    AllowAllSyscall,
    AllowOnce,
    BlockAllSyscallHard,
    BlockAllSyscallSoft,
    BlockOnceHard,
    BlockOnceSoft,
    Empty,
    ShowCommands,
    Unknown(String),
}

impl From<&str> for UserResponse {
    fn from(s: &str) -> Self {
        match s {
            "a" => UserResponse::AllowOnce,
            "aa" => UserResponse::AllowAllSyscall,
            "bh" => UserResponse::BlockOnceHard,
            "bs" => UserResponse::BlockOnceSoft,
            "bah" => UserResponse::BlockAllSyscallHard,
            "bas" => UserResponse::BlockAllSyscallSoft,
            "" => UserResponse::Empty,
            "?" => UserResponse::ShowCommands,
            _ => UserResponse::Unknown(String::from(s)),
        }
    }
}

impl From<&UserResponse> for String {
    fn from(x: &UserResponse) -> Self {
        match x {
            UserResponse::AllowOnce => String::from("a"),
            UserResponse::AllowAllSyscall => String::from("aa"),
            UserResponse::BlockOnceHard => String::from("bh"),
            UserResponse::BlockOnceSoft => String::from("bs"),
            UserResponse::BlockAllSyscallHard => String::from("bah"),
            UserResponse::BlockAllSyscallSoft => String::from("bas"),
            UserResponse::Empty => String::from(""),
            UserResponse::ShowCommands => String::from("?"),
            UserResponse::Unknown(_) => String::new(),
        }
    }
}
