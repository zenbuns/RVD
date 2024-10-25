use rusqlite::Connection;
use anyhow::{Result, Context};

pub fn create_tables(conn: &Connection) -> Result<()> {
	conn.execute_batch(
		"
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
	).context("Failed to create tables")?;

	Ok(())
}
