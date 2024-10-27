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

        -- Existing vulnerability table
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            vulnerability_id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT UNIQUE NOT NULL,
            description TEXT,
            severity TEXT NOT NULL,
            impact TEXT,
            mitigation TEXT,
            published_date TEXT
        );

        -- Existing indexes
        CREATE INDEX IF NOT EXISTS idx_vulnerability_search
        ON vulnerabilities(cve_id, description);

        CREATE INDEX IF NOT EXISTS idx_vulnerability_sort
        ON vulnerabilities(severity, published_date);

        -- Software product tracking
        CREATE TABLE IF NOT EXISTS software_products (
            product_id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_name TEXT NOT NULL,
            vendor TEXT NOT NULL,
            description TEXT,
            UNIQUE(product_name, vendor)
        );

        -- Software versions
        CREATE TABLE IF NOT EXISTS software_versions (
            version_id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            version_number TEXT NOT NULL,
            release_date TEXT,
            FOREIGN KEY (product_id) REFERENCES software_products(product_id),
            UNIQUE(product_id, version_number)
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

        -- Software indexes
        CREATE INDEX IF NOT EXISTS idx_software_product_search
        ON software_products(product_name, vendor);

        CREATE INDEX IF NOT EXISTS idx_software_version_lookup
        ON software_versions(product_id, version_number);

        CREATE INDEX IF NOT EXISTS idx_affected_software_lookup
        ON affected_software(vulnerability_id, version_id);
        "
	).context("Failed to create tables")?;

	Ok(())
}

/// Check and upgrade schema version if needed
pub fn check_schema_version(conn: &Connection) -> Result<()> {
	let current_version = get_schema_version(conn)?;

	// Apply migrations based on current version
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
			// Latest version - no migration needed
			info!("Database schema is up to date");
		}
		v => {
			warn!("Unknown schema version: {}. No migration applied", v);
		}
	}

	Ok(())
}

fn get_schema_version(conn: &Connection) -> Result<i32> {
	// Create version table if it doesn't exist
	conn.execute_batch(
		"CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            installed_on TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            description TEXT NOT NULL
        );"
	)?;

	// Get current version
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
		"
        -- Ensure core tables exist
        CREATE TABLE IF NOT EXISTS vulnerabilities (
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
        ON vulnerabilities(severity, published_date);
        "
	)?;

	Ok(())
}

fn apply_software_tracking_migration(conn: &Connection) -> Result<()> {
	info!("Applying software tracking migration");

	conn.execute_batch(
		"
        -- Add software tracking tables
        CREATE TABLE IF NOT EXISTS software_products (
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
        );
        "
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

		// Verify tables exist
		let tables: Vec<String> = conn
			.prepare("SELECT name FROM sqlite_master WHERE type='table'")?
			.query_map([], |row| row.get(0))?
			.collect::<Result<Vec<_>, _>>()?;

		assert!(tables.contains(&"vulnerabilities".to_string()));
		assert!(tables.contains(&"software_products".to_string()));
		assert!(tables.contains(&"software_versions".to_string()));

		Ok(())
	}

	#[test]
	fn test_schema_version_management() -> Result<()> {
		let conn = setup_test_db()?;

		// Test initial version
		assert_eq!(get_schema_version(&conn)?, 0);

		// Test version update
		update_schema_version(&conn, 1, "Test migration")?;
		assert_eq!(get_schema_version(&conn)?, 1);

		Ok(())
	}

	#[test]
	fn test_migrations() -> Result<()> {
		let conn = setup_test_db()?;

		// Apply migrations
		check_schema_version(&conn)?;

		// Verify we're at the latest version
		assert_eq!(get_schema_version(&conn)?, 2);

		Ok(())
	}
}