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

	// Create connection manager with advanced configuration
	let manager = SqliteConnectionManager::file(&custom_path)
		.with_init(|conn| {
			// Enable foreign key constraints
			conn.execute_batch("PRAGMA foreign_keys = ON;")?;
			// Set journal mode to WAL for better concurrency
			conn.execute_batch("PRAGMA journal_mode = WAL;")?;
			// Set busy timeout
			conn.execute_batch("PRAGMA busy_timeout = 5000;")?;
			// Enable extended error codes
			conn.execute_batch("PRAGMA extended_result_codes = ON;")?;
			Ok(())
		});

	// Build connection pool with optimized settings
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
	use std::thread;
	use std::time::Duration;
	use rusqlite::params;
	use super::*;
	use tempfile::tempdir;

	#[test]
	fn test_establish_pool() -> Result<()> {
		let temp_dir = tempdir()?;
		let db_path = temp_dir.path().join("test.db");

		let pool = establish_pool_with_path(db_path.clone())?;
		let conn = pool.get()?;

		// Verify tables exist
		let tables: Vec<String> = conn
			.prepare("SELECT name FROM sqlite_master WHERE type='table'")?
			.query_map([], |row| row.get(0))?
			.collect::<Result<Vec<_>, _>>()?;

		// Check all required tables exist
		let required_tables = [
			"vulnerabilities",
			"robots",
			"software_products",
			"software_versions",
			"robot_software",
			"affected_software",
			"schema_version"
		];

		for table in required_tables.iter() {
			assert!(tables.contains(&table.to_string()));
		}

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
	fn test_connection_timeout() -> Result<()> {
		let temp_dir = tempdir()?;
		let db_path = temp_dir.path().join("timeout_test.db");

		let pool = Pool::builder()
			.max_size(1)
			.connection_timeout(Duration::from_millis(100))
			.build(SqliteConnectionManager::file(&db_path))
			.context("Failed to build connection pool")?;

		// Hold the only connection
		let _conn = pool.get()?;

		// Try to get another connection - should timeout
		assert!(pool.get().is_err());

		Ok(())
	}

	#[test]
	fn test_default_path() {
		let path = get_default_db_path();
		assert!(path.ends_with("database/vulnerabilities.db"));
	}

	#[test]
	fn test_connection_concurrency() -> Result<()> {
		let temp_dir = tempdir()?;
		let db_path = temp_dir.path().join("concurrency_test.db");
		let pool = establish_pool_with_path(db_path)?;

		// Initialize test table
		let conn = pool.get()?;
		conn.execute_batch(
			"CREATE TABLE IF NOT EXISTS test_concurrent (
				id INTEGER PRIMARY KEY,
				value TEXT NOT NULL
			);"
		)?;

		// Spawn multiple threads to test concurrent access
		let handles: Vec<_> = (0..10)
			.map(|i| {
				let pool = pool.clone();
				thread::spawn(move || -> Result<()> {
					let conn = pool.get()?;
					conn.execute(
						"INSERT INTO test_concurrent (value) VALUES (?)",
						params![format!("value_{}", i)],
					)?;
					Ok(())
				})
			})
			.collect();

		// Wait for all threads and check results
		for handle in handles {
			handle.join().unwrap()?;
		}

		// Verify all insertions succeeded
		let count: i64 = conn.query_row(
			"SELECT COUNT(*) FROM test_concurrent",
			[],
			|row| row.get(0)
		)?;
		assert_eq!(count, 10);

		Ok(())
	}

	#[test]
	fn test_connection_resilience() -> Result<()> {
		let temp_dir = tempdir()?;
		let db_path = temp_dir.path().join("resilience_test.db");
		let pool = establish_pool_with_path(db_path.clone())?;

		// Test connection recovery after temporary file system issues
		let handles: Vec<_> = (0..5)
			.map(|_| {
				let pool = pool.clone();
				let db_path = db_path.clone();
				thread::spawn(move || -> Result<()> {
					// Simulate intermittent filesystem issues
					if let Some(parent) = db_path.parent() {
						let _ = std::fs::create_dir_all(parent);
					}

					let conn = pool.get()?;
					conn.execute_batch("PRAGMA quick_check;")?;
					Ok(())
				})
			})
			.collect();

		for handle in handles {
			handle.join().unwrap()?;
		}

		Ok(())
	}

	#[test]
	fn test_connection_initialization() -> Result<()> {
		let temp_dir = tempdir()?;
		let db_path = temp_dir.path().join("init_test.db");
		let pool = establish_pool_with_path(db_path)?;
		let conn = pool.get()?;

		// Verify PRAGMA settings
		let foreign_keys: i32 = conn.query_row(
			"PRAGMA foreign_keys",
			[],
			|row| row.get(0)
		)?;
		assert_eq!(foreign_keys, 1);

		let journal_mode: String = conn.query_row(
			"PRAGMA journal_mode",
			[],
			|row| row.get(0)
		)?;
		assert_eq!(journal_mode.to_uppercase(), "WAL");

		let busy_timeout: i32 = conn.query_row(
			"PRAGMA busy_timeout",
			[],
			|row| row.get(0)
		)?;
		assert!(busy_timeout >= 5000);

		Ok(())
	}

	#[test]
	fn test_connection_pool_limits() -> Result<()> {
		let temp_dir = tempdir()?;
		let db_path = temp_dir.path().join("pool_test.db");

		let pool = Pool::builder()
			.max_size(2)
			.min_idle(Some(1))
			.connection_timeout(Duration::from_millis(100))
			.build(SqliteConnectionManager::file(&db_path))
			.context("Failed to build connection pool")?;

		// Get connections up to max_size
		let conn1 = pool.get()?;
		let conn2 = pool.get()?;

		// Third connection should fail
		assert!(pool.get().is_err());

		// Release one connection
		drop(conn1);

		// Should be able to get a connection again
		let _conn3 = pool.get()?;

		// Clean up
		drop(conn2);

		Ok(())
	}

	#[test]
	fn test_get_conn_helper() -> Result<()> {
		let temp_dir = tempdir()?;
		let db_path = temp_dir.path().join("helper_test.db");
		let pool = establish_pool_with_path(db_path)?;

		// Test the get_conn helper function
		let conn = get_conn(&pool)?;

		// Verify connection works
		conn.execute_batch("PRAGMA quick_check;")?;

		Ok(())
	}
}