use clap::{App, AppSettings, Arg, ArgMatches, crate_version};

#[derive(Debug)]
pub struct AppConfig<'a> {
    pub args: ArgMatches<'a>,
}

impl<'a> AppConfig<'a> {
    pub fn new() -> Self {
        let matches = App::new("syswall")
            .version(crate_version!())
            .about("Syswall: a firewall for syscalls")
            .author("Simon Pugnet")
            .setting(AppSettings::TrailingVarArg)
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
                    .help("Whether to save the resulting tracee config to a file (see --config-file)")
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
        Self {
            args: matches,
        }
    }
}
