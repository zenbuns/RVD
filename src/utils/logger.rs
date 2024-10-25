use env_logger::{Builder, Env};

pub fn init() {
	Builder::from_env(Env::default().default_filter_or("info"))
		.format_timestamp_millis()
		.format_module_path(true)
		.init();
}