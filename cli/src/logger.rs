use log::{Level, Metadata, Record};

pub struct AppLogger;

impl log::Log for AppLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let prefix = match record.level() {
            Level::Error => "ERROR: ",
            Level::Warn => "WARNING: ",
            _ => "",
        };
        if self.enabled(record.metadata()) {
            eprintln!("{}{}", prefix, record.args());
        }
    }

    fn flush(&self) {}
}
