use clap::{crate_version, App as ClapApp, AppSettings, Arg, ArgMatches};
use log::{info, LevelFilter};
use std::io;

use crate::logger::AppLogger;

static LOGGER: AppLogger = AppLogger;

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

#[derive(Debug)]
pub struct App<'a> {
    pub args: ArgMatches<'a>,
}

impl<'a> App<'a> {
    pub fn new() -> Self {
        let matches = ClapApp::new("syswall")
            .version(crate_version!())
            .about("Syswall: a firewall for syscalls")
            .author("Simon Pugnet")
            .setting(AppSettings::TrailingVarArg)
            .arg(
                Arg::with_name("verbose")
                    .short("v")
                    .long("verbose")
                    .help("Increases verbosity of program output (can be specified multiple times)")
                    .takes_value(false)
                    .multiple(true)
            )
            .arg(
                Arg::with_name("load_config")
                    .short("l")
                    .long("load-config")
                    .help("Whether to load a previously saved config (see --config-file)")
                    .takes_value(false)
                    .requires("config_file")
            )
            .arg(
                Arg::with_name("save_config")
                    .short("s")
                    .long("save-config")
                    .help(
                        "Whether to save the resulting tracee config to a file (see --config-file)",
                    )
                    .takes_value(false)
                    .requires("config_file")
            )
            .arg(
                Arg::with_name("config_file")
                    .short("f")
                    .long("config-file")
                    .value_name("FILENAME")
                    .help("Name of process config JSON to load/save")
                    .takes_value(true)
            )
            .arg(
                Arg::with_name("tracee_cmd")
                    .raw(true)
                    .help("Full tracee command and arguments (e.g. \"ls -l\")")
                    .required(true)
            )
            .get_matches();

        // Set up logger
        let level_filter = match matches.occurrences_of("verbose") {
            0 => LevelFilter::Info,
            1 => LevelFilter::Debug,
            _ => LevelFilter::Trace,
        };
        if log::set_logger(&LOGGER)
            .map(|()| log::set_max_level(level_filter))
            .is_err()
        {
            eprintln!("ERROR: unable to set application logger instance");
        }

        Self { args: matches }
    }

    pub fn get_user_input(&self, default: UserResponse) -> Result<UserResponse, &'static str> {
        let mut buffer = String::new();
        let def_str: String = String::from(&default);
        loop {
            eprint!(" - Choice (\"{}\" default, ? for help): ", def_str);
            buffer.clear();
            io::stdin()
                .read_line(&mut buffer)
                .map_err(|_| "Unable to read from stdin")?;
            let inp = buffer.trim();
            let resp = UserResponse::from(inp);
            match resp {
                UserResponse::ShowCommands => self.show_commands(),
                UserResponse::Empty => return Ok(default),
                UserResponse::Unknown(s) => {
                    info!("Unknown command \"{}\"", s);
                    self.show_commands();
                }
                _ => return Ok(resp),
            }
        }
    }

    pub fn show_commands(&self) {
        info!(" - Available commands: -");
        info!("   a:   allow this syscall once");
        info!("   aa:  allow this syscall always from now on");
        info!("   bh:  hard-block this syscall once (tracee sees error)");
        info!("   bs:  soft-block this syscall once (tracee sees success)");
        info!("   bah: always hard-block this syscall from now on");
        info!("   bas: always soft-block this syscall from now on");
    }
}
