use std::io;

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
            "a"   => UserResponse::AllowOnce,
            "aa"  => UserResponse::AllowAllSyscall,
            "bh"  => UserResponse::BlockOnceHard,
            "bs"  => UserResponse::BlockOnceSoft,
            "bah" => UserResponse::BlockAllSyscallHard,
            "bas" => UserResponse::BlockAllSyscallSoft,
            ""    => UserResponse::Empty,
            "?"   => UserResponse::ShowCommands,
            _     => UserResponse::Unknown(String::from(s)),
        }
    }
}

impl From<&UserResponse> for String {
    fn from(x: &UserResponse) -> Self {
        match x {
            UserResponse::AllowOnce           => String::from("a"),
            UserResponse::AllowAllSyscall     => String::from("aa"),
            UserResponse::BlockOnceHard       => String::from("bh"),
            UserResponse::BlockOnceSoft       => String::from("bs"),
            UserResponse::BlockAllSyscallHard => String::from("bah"),
            UserResponse::BlockAllSyscallSoft => String::from("bas"),
            UserResponse::Empty               => String::from(""),
            UserResponse::ShowCommands        => String::from("?"),
            UserResponse::Unknown(_)          => String::new(),
        }
    }
}

pub fn get_user_input(default: UserResponse) -> UserResponse {
    let mut buffer = String::new();
    let def_str: String = String::from(&default);
    loop {
        eprint!(" - Choice (\"{}\" default, ? for help): ", def_str);
        buffer.clear();
        io::stdin().read_line(&mut buffer).expect("Unable to read from stdin");
        let inp = buffer.trim();
        let resp = UserResponse::from(inp);
        match resp {
            UserResponse::ShowCommands => show_commands(),
            UserResponse::Empty => return default,
            UserResponse::Unknown(s) => {
                eprintln!("Unknown command \"{}\"", s);
                show_commands();
            },
            _ => return resp,
        }
    }
}

fn show_commands() {
    eprintln!(" - Available commands: -");
    eprintln!("   a: allow this syscall once");
    eprintln!("   aa: allow this syscall always from now on");
    eprintln!("   bh: hard-block this syscall once (tracee sees error)");
    eprintln!("   bs: soft-block this syscall once (tracee sees success)");
    eprintln!("   bah: always hard-block this syscall from now on");
    eprintln!("   bas: always soft-block this syscall from now on");
}
