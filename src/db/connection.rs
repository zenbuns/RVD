use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use std::path::PathBuf;
use anyhow::{Result, Context};
use log::info;

pub type SqlitePool = Pool<SqliteConnectionManager>;

/// Establishes a connection pool with a custom database path
pub fn establish_pool_with_path(custom_path: PathBuf) -> Result<SqlitePool> {
	info!("SQLite database will be located at: {:?}", custom_path);

	std::fs::create_dir_all(custom_path.parent().unwrap())
		.context("Failed to create database directory")?;

	let manager = SqliteConnectionManager::file(custom_path);

	let pool = Pool::builder()
		.max_size(15)
		.build(manager)
		.context("Failed to create SQLite connection pool")?;

	info!("SQLite connection pool established successfully");
	Ok(pool)
}

/// Establishes a connection pool with a default database path
pub fn establish_pool() -> Result<SqlitePool> {
	let default_path = get_default_db_path();
	establish_pool_with_path(default_path)
}

/// Gets the default database path
fn get_default_db_path() -> PathBuf {
	// Create path relative to the current directory
	let mut db_path = PathBuf::from(".");
	db_path.push("database");
	db_path.push("vulnerabilities.db");
	db_path
}
