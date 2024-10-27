// src/db/schema.rs

use rusqlite::{Connection, params};
use anyhow::{Result, Context};
use log::{info, warn};

/// Initialize the database schema
pub fn create_tables(conn: &Connection) -> Result<()> {
	conn.execute_batch(
		"
		-- Schema version tracking
		CREATE TABLE IF NOT EXISTS schema_version (
			version INTEGER PRIMARY KEY,
			installed_on TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			description TEXT NOT NULL
		);

		-- Vulnerabilities table
		CREATE TABLE IF NOT EXISTS vulnerabilities (
			vulnerability_id INTEGER PRIMARY KEY AUTOINCREMENT,
			cve_id TEXT UNIQUE NOT NULL,
			description TEXT,
			severity TEXT NOT NULL,
			impact TEXT,
			mitigation TEXT,
			published_date TEXT
		);

		-- Vulnerability indexes
		CREATE INDEX IF NOT EXISTS idx_vulnerability_search
		ON vulnerabilities(cve_id, description);

		CREATE INDEX IF NOT EXISTS idx_vulnerability_sort
		ON vulnerabilities(severity, published_date);

		-- Robots table
		CREATE TABLE IF NOT EXISTS robots (
			robot_id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			manufacturer TEXT,
			specifications TEXT,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);

		-- Robot indexes
		CREATE INDEX IF NOT EXISTS idx_robot_search
		ON robots(name, manufacturer);

		-- Software products table
		CREATE TABLE IF NOT EXISTS software_products (
			product_id INTEGER PRIMARY KEY AUTOINCREMENT,
			product_name TEXT NOT NULL,
			vendor TEXT NOT NULL,
			description TEXT,
			UNIQUE(product_name, vendor)
		);

		-- Software versions table
		CREATE TABLE IF NOT EXISTS software_versions (
			version_id INTEGER PRIMARY KEY AUTOINCREMENT,
			product_id INTEGER NOT NULL,
			version_number TEXT NOT NULL,
			release_date TEXT,
			FOREIGN KEY (product_id) REFERENCES software_products(product_id),
			UNIQUE(product_id, version_number)
		);

		-- Robot software mapping
		CREATE TABLE IF NOT EXISTS robot_software (
			robot_id INTEGER NOT NULL,
			version_id INTEGER NOT NULL,
			installed_date TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (robot_id, version_id),
			FOREIGN KEY (robot_id) REFERENCES robots(robot_id) ON DELETE CASCADE,
			FOREIGN KEY (version_id) REFERENCES software_versions(version_id)
		);

		-- Affected software tracking
		CREATE TABLE IF NOT EXISTS affected_software (
			vulnerability_id INTEGER NOT NULL,
			version_id INTEGER NOT NULL,
			affected_version_pattern TEXT NOT NULL,
			fixed_in_version TEXT,
			detection_confidence REAL NOT NULL DEFAULT 1.0,
			PRIMARY KEY (vulnerability_id, version_id),
			FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(vulnerability_id),
			FOREIGN KEY (version_id) REFERENCES software_versions(version_id)
		);

		-- Additional indexes
		CREATE INDEX IF NOT EXISTS idx_software_product_search
		ON software_products(product_name, vendor);

		CREATE INDEX IF NOT EXISTS idx_software_version_lookup
		ON software_versions(product_id, version_number);

		CREATE INDEX IF NOT EXISTS idx_affected_software_lookup
		ON affected_software(vulnerability_id, version_id);

		CREATE INDEX IF NOT EXISTS idx_robot_software_lookup
		ON robot_software(robot_id, version_id);
		"
	).context("Failed to create tables")?;

	Ok(())
}

/// Check and upgrade schema version if needed
pub fn check_schema_version(conn: &Connection) -> Result<()> {
	let current_version = get_schema_version(conn)?;

	match current_version {
		0 => {
			apply_initial_migration(conn)?;
			update_schema_version(conn, 1, "Initial schema")?;
		}
		1 => {
			apply_software_tracking_migration(conn)?;
			update_schema_version(conn, 2, "Added software tracking")?;
		}
		2 => {
			apply_robot_migration(conn)?;
			update_schema_version(conn, 3, "Added robot management")?;
		}
		3 => {
			info!("Database schema is up to date");
		}
		v => {
			warn!("Unknown schema version: {}. No migration applied", v);
		}
	}

	Ok(())
}

fn get_schema_version(conn: &Connection) -> Result<i32> {
	conn.execute_batch(
		"CREATE TABLE IF NOT EXISTS schema_version (
			version INTEGER PRIMARY KEY,
			installed_on TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			description TEXT NOT NULL
		);"
	)?;

	let version: i32 = conn.query_row(
		"SELECT COALESCE(MAX(version), 0) FROM schema_version",
		[],
		|row| row.get(0)
	)?;

	Ok(version)
}

fn update_schema_version(conn: &Connection, version: i32, description: &str) -> Result<()> {
	conn.execute(
		"INSERT INTO schema_version (version, description) VALUES (?, ?)",
		params![version, description],
	)?;

	info!("Updated schema to version {} - {}", version, description);
	Ok(())
}

fn apply_initial_migration(conn: &Connection) -> Result<()> {
	info!("Applying initial schema migration");

	conn.execute_batch(
		"CREATE TABLE IF NOT EXISTS vulnerabilities (
			vulnerability_id INTEGER PRIMARY KEY AUTOINCREMENT,
			cve_id TEXT UNIQUE NOT NULL,
			description TEXT,
			severity TEXT NOT NULL,
			impact TEXT,
			mitigation TEXT,
			published_date TEXT
		);

		CREATE INDEX IF NOT EXISTS idx_vulnerability_search
		ON vulnerabilities(cve_id, description);

		CREATE INDEX IF NOT EXISTS idx_vulnerability_sort
		ON vulnerabilities(severity, published_date);"
	)?;

	Ok(())
}

fn apply_software_tracking_migration(conn: &Connection) -> Result<()> {
	info!("Applying software tracking migration");

	conn.execute_batch(
		"CREATE TABLE IF NOT EXISTS software_products (
			product_id INTEGER PRIMARY KEY AUTOINCREMENT,
			product_name TEXT NOT NULL,
			vendor TEXT NOT NULL,
			description TEXT,
			UNIQUE(product_name, vendor)
		);

		CREATE TABLE IF NOT EXISTS software_versions (
			version_id INTEGER PRIMARY KEY AUTOINCREMENT,
			product_id INTEGER NOT NULL,
			version_number TEXT NOT NULL,
			release_date TEXT,
			FOREIGN KEY (product_id) REFERENCES software_products(product_id),
			UNIQUE(product_id, version_number)
		);

		CREATE TABLE IF NOT EXISTS affected_software (
			vulnerability_id INTEGER NOT NULL,
			version_id INTEGER NOT NULL,
			affected_version_pattern TEXT NOT NULL,
			fixed_in_version TEXT,
			detection_confidence REAL NOT NULL DEFAULT 1.0,
			PRIMARY KEY (vulnerability_id, version_id),
			FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(vulnerability_id),
			FOREIGN KEY (version_id) REFERENCES software_versions(version_id)
		);"
	)?;

	Ok(())
}

fn apply_robot_migration(conn: &Connection) -> Result<()> {
	info!("Applying robot management migration");

	conn.execute_batch(
		"CREATE TABLE IF NOT EXISTS robots (
			robot_id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			manufacturer TEXT,
			specifications TEXT,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS robot_software (
			robot_id INTEGER NOT NULL,
			version_id INTEGER NOT NULL,
			installed_date TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (robot_id, version_id),
			FOREIGN KEY (robot_id) REFERENCES robots(robot_id) ON DELETE CASCADE,
			FOREIGN KEY (version_id) REFERENCES software_versions(version_id)
		);

		CREATE INDEX IF NOT EXISTS idx_robot_search
		ON robots(name, manufacturer);

		CREATE INDEX IF NOT EXISTS idx_robot_software_lookup
		ON robot_software(robot_id, version_id);"
	)?;

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use rusqlite::Connection;
	use tempfile::tempdir;

	fn setup_test_db() -> Result<Connection> {
		let dir = tempdir()?;
		let path = dir.path().join("test.db");
		let conn = Connection::open(path)?;
		Ok(conn)
	}

	#[test]
	fn test_schema_creation() -> Result<()> {
		let conn = setup_test_db()?;
		create_tables(&conn)?;

		let tables: Vec<String> = conn
			.prepare("SELECT name FROM sqlite_master WHERE type='table'")?
			.query_map([], |row| row.get(0))?
			.collect::<Result<Vec<_>, _>>()?;

		assert!(tables.contains(&"vulnerabilities".to_string()));
		assert!(tables.contains(&"robots".to_string()));
		assert!(tables.contains(&"software_products".to_string()));
		assert!(tables.contains(&"software_versions".to_string()));
		assert!(tables.contains(&"robot_software".to_string()));
		assert!(tables.contains(&"affected_software".to_string()));

		Ok(())
	}

	#[test]
	fn test_schema_version_management() -> Result<()> {
		let conn = setup_test_db()?;
		assert_eq!(get_schema_version(&conn)?, 0);
		update_schema_version(&conn, 1, "Test migration")?;
		assert_eq!(get_schema_version(&conn)?, 1);
		Ok(())
	}

	#[test]
	fn test_migrations() -> Result<()> {
		let conn = setup_test_db()?;
		check_schema_version(&conn)?;
		assert_eq!(get_schema_version(&conn)?, 3);
		Ok(())
	}
}