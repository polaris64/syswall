mod app;
mod logger;

use log::{debug, error, info, warn};

use syswall;
use syswall::tracer_conf::{RuntimeConf, TracerConf};
use syswall::user_response::UserResponse;

use crate::app::App;

fn main() -> Result<(), String> {
    let app = App::new();

    // Get the tracee command as a Vec<&str>
    let child_cmd = app
        .args
        .values_of("tracee_cmd")
        .ok_or("Unable to get tracee command")?
        .collect::<Vec<&str>>();

    // Load TracerConf from file if necessary
    let mut conf: TracerConf = if app.args.is_present("load_config") {
        match app.args.value_of("config_file") {
            Some(filename) => match TracerConf::from_file(filename) {
                Ok(c) => {
                    debug!("Configuration loaded from {}", filename);
                    c
                }
                Err(e) => {
                    error!(
                        "Unable to read process configuration from file {}: {}",
                        filename, e
                    );
                    TracerConf::default()
                }
            },
            None => TracerConf::default(),
        }
    } else {
        TracerConf::default()
    };

    // Build a RuntimeConf and create a syscall_cb closure to ask the user for decisions via stdin
    // when necessary.
    let mut runtime_conf = RuntimeConf::default();
    runtime_conf.set_syscall_cb(Box::new(|query| {
        info!("{}", query.description);
        match query.configured_choice {
            None => Some(
                app.get_user_input(UserResponse::AllowOnce)
                    .unwrap_or(UserResponse::AllowOnce),
            ),
            Some(_) => None,
        }
    }));

    // Trace the process
    let process_states = syswall::trace(child_cmd, &mut conf, &runtime_conf)?;

    // Print final report
    info!(
        "\n{}",
        process_states
            .0
            .iter()
            .map(|(pid, st)| {
                let report = st.report();
                if report.is_empty() {
                    format!("Nothing to report for {:?}", pid)
                } else {
                    format!("Final state for {:?}: -{}", pid, report)
                }
            })
            .collect::<Vec<String>>()
            .join("\n\n")
    );

    // Save the process config based on args
    if app.args.is_present("save_config") {
        match app.args.value_of("config_file") {
            Some(filename) => {
                if let Err(e) = conf.write_to_file(filename) {
                    error!("Unable to write process configuration to file {}: {}", filename, e);
                }
            },
            None => warn!("The program was requested to save the tracee configuration, but no filename was specified"),
        };
    }

    Ok(())
}
