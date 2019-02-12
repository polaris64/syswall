use std::io;

pub enum UserResponse {
    AllowAllSyscall,
    AllowOnce,
    BlockAllSyscallHard,
    BlockAllSyscallSoft,
    BlockOnceHard,
    BlockOnceSoft,
    Unknown(String),
}

pub fn get_user_input(default: UserResponse) -> UserResponse {
    let mut buffer = String::new();
    loop {
        eprint!("Choice (\"{}\" default, ? for help): ", command_from_user_response(&default));
        buffer.clear();
        io::stdin().read_line(&mut buffer).expect("Unable to read from stdin");
        let inp = buffer.trim();
        match inp {
            "?" => show_commands(),
            "a" => return UserResponse::AllowOnce,
            "aa" => return UserResponse::AllowAllSyscall,
            "bh" => return UserResponse::BlockOnceHard,
            "bs" => return UserResponse::BlockOnceSoft,
            "bah" => return UserResponse::BlockAllSyscallHard,
            "bas" => return UserResponse::BlockAllSyscallSoft,
            "" => return default,
            _ => return UserResponse::Unknown(String::from(inp)),
        };
    }
}

fn show_commands() {
    eprintln!("Available commands: -");
    eprintln!("  a: allow this syscall once");
    eprintln!("  aa: allow this syscall always from now on");
    eprintln!("  bh: hard-block this syscall once (tracee sees error)");
    eprintln!("  bs: soft-block this syscall once (tracee sees success)");
    eprintln!("  bah: always hard-block this syscall from now on");
    eprintln!("  bas: always soft-block this syscall from now on");
}

fn command_from_user_response(v: &UserResponse) -> &'static str {
    match v {
        UserResponse::AllowOnce => "a",
        UserResponse::AllowAllSyscall => "aa",
        UserResponse::BlockOnceHard => "bh",
        UserResponse::BlockOnceSoft => "bs",
        UserResponse::BlockAllSyscallHard => "bah",
        UserResponse::BlockAllSyscallSoft => "bas",
        UserResponse::Unknown(_) => "",
    }
}
