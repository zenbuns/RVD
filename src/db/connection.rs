// src/db/connection.rs

use crate::db::schema;
use anyhow::{Context, Result};
use log::{error, info};
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use std::path::PathBuf;

pub type SqlitePool = Pool<SqliteConnectionManager>;
pub type SqliteConnection = PooledConnection<SqliteConnectionManager>;

/// Establishes a connection pool with a custom database path
pub fn establish_pool_with_path(custom_path: PathBuf) -> Result<SqlitePool> {
	info!("SQLite database will be located at: {:?}", custom_path);

	// Ensure database directory exists
	if let Some(parent) = custom_path.parent() {
		std::fs::create_dir_all(parent)
			.context("Failed to create database directory")?;
	}

	// Create connection manager
	let manager = SqliteConnectionManager::file(&custom_path)
		.with_init(|conn| {
			// Enable foreign key constraints
			conn.execute_batch("PRAGMA foreign_keys = ON;")?;
			// Set journal mode to WAL for better concurrency
			conn.execute_batch("PRAGMA journal_mode = WAL;")?;
			Ok(())
		});

	// Build connection pool
	let pool = Pool::builder()
		.max_size(15)
		.min_idle(Some(5))
		.connection_timeout(std::time::Duration::from_secs(10))
		.build(manager)
		.context("Failed to create SQLite connection pool")?;

	// Initialize database schema
	match pool.get() {
		Ok(conn) => {
			// Create tables if they don't exist
			schema::create_tables(&conn)
				.context("Failed to initialize database schema")?;

			// Check and apply any pending migrations
			schema::check_schema_version(&conn)
				.context("Failed to check/apply schema migrations")?;

			info!("Database schema initialized successfully");
		}
		Err(e) => {
			error!("Failed to get initial database connection: {}", e);
			return Err(e).context("Failed to initialize database");
		}
	}

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
	let mut db_path = PathBuf::from(".");
	db_path.push("database");
	db_path.push("vulnerabilities.db");
	db_path
}

/// Helper function to get a connection from the pool with proper error context
pub fn get_conn(pool: &SqlitePool) -> Result<SqliteConnection> {
	pool.get()
		.context("Failed to get database connection from pool")
}

#[cfg(test)]
mod tests {
	use super::*;
	use tempfile::tempdir;

	#[test]
	fn test_establish_pool() -> Result<()> {
		let temp_dir = tempdir()?;
		let db_path = temp_dir.path().join("test.db");

		let pool = establish_pool_with_path(db_path.clone())?;

		// Test connection works
		let conn = pool.get()?;

		// Verify tables were created
		let tables: Vec<String> = conn
			.prepare("SELECT name FROM sqlite_master WHERE type='table'")?
			.query_map([], |row| row.get(0))?
			.collect::<Result<Vec<_>, _>>()?;

		// Check required tables exist
		assert!(tables.contains(&"vulnerabilities".to_string()));
		assert!(tables.contains(&"software_products".to_string()));
		assert!(tables.contains(&"software_versions".to_string()));
		assert!(tables.contains(&"affected_software".to_string()));
		assert!(tables.contains(&"schema_version".to_string()));

		// Verify foreign keys are enabled
		let foreign_keys: i32 = conn.query_row(
			"PRAGMA foreign_keys",
			[],
			|row| row.get(0)
		)?;
		assert_eq!(foreign_keys, 1);

		// Test concurrent connections
		let handles: Vec<_> = (0..5)
			.map(|i| {
				let pool = pool.clone();
				std::thread::spawn(move || {
					let conn = pool.get().unwrap();
					conn.execute(
						"SELECT * FROM schema_version",
						[],
					).unwrap();
					i
				})
			})
			.collect();

		for handle in handles {
			handle.join().unwrap();
		}

		Ok(())
	}

	#[test]
	fn test_connection_timeout() {
		let temp_dir = tempdir().unwrap();
		let db_path = temp_dir.path().join("timeout_test.db");

		let pool = Pool::builder()
			.max_size(1)
			.connection_timeout(std::time::Duration::from_millis(100))
			.build(SqliteConnectionManager::file(&db_path))
			.unwrap();

		// Hold the only connection
		let _conn = pool.get().unwrap();

		// Try to get another connection - should timeout
		assert!(pool.get().is_err());
	}

	#[test]
	fn test_default_path() {
		let path = get_default_db_path();
		assert!(path.ends_with("database/vulnerabilities.db"));
	}
}