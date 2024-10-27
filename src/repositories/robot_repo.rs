// src/repositories/robot_repo.rs

use crate::db::connection::SqlitePool;
use crate::models::robot::Robot;
use rusqlite::params;
use std::sync::Arc;
use anyhow::{Result, Context};
use tokio::task;

pub struct RobotRepository {
	pool: Arc<SqlitePool>,
}

impl RobotRepository {
	pub fn new(pool: Arc<SqlitePool>) -> Self {
		Self { pool }
	}

	/// Add a new robot with its software components
	pub async fn add_robot(&self, robot: Robot) -> Result<i64> {
		let pool = self.pool.clone();
		task::spawn_blocking(move || {
			let mut conn = pool.get().context("Failed to get database connection")?;
			let tx = conn.transaction()?;

			// Insert into software_products if not exists
			tx.execute(
				"INSERT OR IGNORE INTO software_products (product_name, vendor, description)
                 VALUES (?1, ?2, ?3)",
				params![
                    robot.name.clone(),
                    robot.manufacturer.clone(),
                    robot.specifications.clone(),
                ],
			)?;

			// Get the product_id
			let product_id: i64 = tx.query_row(
				"SELECT product_id FROM software_products
                 WHERE product_name = ?1 AND vendor = ?2",
				params![robot.name, robot.manufacturer],
				|row| row.get(0),
			)?;

			// Insert version information
			tx.execute(
				"INSERT INTO software_versions (product_id, version_number, release_date)
                 VALUES (?1, ?2, datetime('now'))",
				params![
                    product_id,
                    robot.specifications.unwrap_or_else(|| "1.0.0".to_string()),
                ],
			)?;

			tx.commit()?;
			Ok(product_id)
		})
			.await
			.context("Failed to execute database operation")?
	}

	/// Get all robots with their associated vulnerability information
	pub async fn get_all_robots(&self) -> Result<Vec<Robot>> {
		let pool = self.pool.clone();
		task::spawn_blocking(move || {
			let conn = pool.get().context("Failed to get database connection")?;
			let mut stmt = conn.prepare(
				"SELECT DISTINCT
                    sp.product_id,
                    sp.product_name,
                    sp.description,
                    sp.vendor,
                    (
                        SELECT COUNT(DISTINCT v.vulnerability_id)
                        FROM vulnerabilities v
                        JOIN affected_software af ON v.vulnerability_id = af.vulnerability_id
                        JOIN software_versions sv ON af.version_id = sv.version_id
                        WHERE sv.product_id = sp.product_id
                    ) as vulnerability_count
                 FROM software_products sp
                 LEFT JOIN software_versions sv ON sp.product_id = sv.product_id"
			)?;

			let robot_iter = stmt.query_map([], |row| {
				Ok(Robot {
					robot_id: Some(row.get(0)?),
					name: row.get(1)?,
					specifications: row.get(2)?,
					manufacturer: row.get(3)?,
				})
			})?;

			robot_iter
				.collect::<rusqlite::Result<Vec<_>>>()
				.context("Failed to collect robots")
		})
			.await
			.context("Failed to execute database operation")?
	}

	/// Get a specific robot with its vulnerability information
	pub async fn get_robot_by_id(&self, id: i64) -> Result<Robot> {
		let pool = self.pool.clone();
		task::spawn_blocking(move || {
			let conn = pool.get().context("Failed to get database connection")?;
			conn.query_row(
				"SELECT
                    sp.product_id,
                    sp.product_name,
                    sp.description,
                    sp.vendor
                 FROM software_products sp
                 WHERE sp.product_id = ?1",
				params![id],
				|row| {
					Ok(Robot {
						robot_id: Some(row.get(0)?),
						name: row.get(1)?,
						specifications: row.get(2)?,
						manufacturer: row.get(3)?,
					})
				},
			)
				.context("Robot not found")
		})
			.await
			.context("Failed to execute database operation")?
	}

	/// Delete a robot and its associated software information
	pub async fn delete_robot(&self, id: i64) -> Result<()> {
		let pool = self.pool.clone();
		task::spawn_blocking(move || {
			let mut conn = pool.get().context("Failed to get database connection")?;
			let tx = conn.transaction()?;

			// Delete associated version vulnerabilities
			tx.execute(
				"DELETE FROM affected_software
                 WHERE version_id IN (
                    SELECT version_id
                    FROM software_versions
                    WHERE product_id = ?1
                 )",
				params![id],
			)?;

			// Delete versions
			tx.execute(
				"DELETE FROM software_versions WHERE product_id = ?1",
				params![id],
			)?;

			// Delete product
			let result = tx.execute(
				"DELETE FROM software_products WHERE product_id = ?1",
				params![id],
			)?;

			if result == 0 {
				anyhow::bail!("Robot not found");
			}

			tx.commit()?;
			Ok(())
		})
			.await
			.context("Failed to execute database operation")?
	}

	/// Get vulnerabilities associated with a robot
	pub async fn get_robot_vulnerabilities(&self, robot_id: i64) -> Result<Vec<(String, String)>> {
		let pool = self.pool.clone();
		task::spawn_blocking(move || {
			let conn = pool.get().context("Failed to get database connection")?;
			let mut stmt = conn.prepare(
				"SELECT DISTINCT v.cve_id, v.severity
                 FROM vulnerabilities v
                 JOIN affected_software af ON v.vulnerability_id = af.vulnerability_id
                 JOIN software_versions sv ON af.version_id = sv.version_id
                 WHERE sv.product_id = ?1
                 ORDER BY v.severity DESC"
			)?;

			let vuln_iter = stmt.query_map([robot_id], |row| {
				Ok((row.get(0)?, row.get(1)?))
			})?;

			vuln_iter
				.collect::<rusqlite::Result<Vec<_>>>()
				.context("Failed to collect vulnerabilities")
		})
			.await
			.context("Failed to execute database operation")?
	}
}
