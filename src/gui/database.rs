use crate::db::connection::SqlitePool;
use crate::models::{robot::Robot, vulnerability::Vulnerability};
use crate::repositories::vulnerability_repo::VulnerabilityRepository;
use super::types::{FilterSeverity, RobotForm, SortField};
use std::sync::Arc;
use log::{error, info, debug};
use tokio::task;
use anyhow::{Result, Context, bail};
use rusqlite::{params, Transaction};
use chrono::NaiveDateTime;

/// Loads vulnerabilities from the database with filtering and sorting.
pub async fn load_vulnerabilities(
	pool: Arc<SqlitePool>,
	search_query: String,
	page: usize,
	page_size: usize,
	sort_field: SortField,
	sort_ascending: bool,
	filter_severity: FilterSeverity,
) -> Result<(Vec<Vulnerability>, usize)> {
	let repo = VulnerabilityRepository::new(pool.clone());

	let (mut vulnerabilities, total_pages) = repo
		.search_vulnerabilities(&search_query, page, page_size)
		.await
		.context("Failed to search vulnerabilities")?;

	// Apply severity filtering
	if !matches!(filter_severity, FilterSeverity::All) {
		let severity = match filter_severity {
			FilterSeverity::High => "high",
			FilterSeverity::Medium => "medium",
			FilterSeverity::Low => "low",
			FilterSeverity::All => unreachable!(),
		};
		vulnerabilities.retain(|v| v.severity.to_lowercase() == severity);
	}

	// Apply sorting
	match sort_field {
		SortField::CVE => {
			vulnerabilities.sort_by(|a, b| {
				if sort_ascending {
					a.cve_id.cmp(&b.cve_id)
				} else {
					b.cve_id.cmp(&a.cve_id)
				}
			});
		},
		SortField::Severity => {
			vulnerabilities.sort_by(|a, b| {
				if sort_ascending {
					a.severity.cmp(&b.severity)
				} else {
					b.severity.cmp(&a.severity)
				}
			});
		},
		SortField::Date => {
			vulnerabilities.sort_by(|a, b| {
				if sort_ascending {
					a.published_date.cmp(&b.published_date)
				} else {
					b.published_date.cmp(&a.published_date)
				}
			});
		},
		SortField::None => (),
		SortField::RobotName | SortField::Manufacturer => (),
	}

	Ok((vulnerabilities, total_pages))
}

/// Loads all robots from the database with their software versions.
pub async fn load_robots(pool: Arc<SqlitePool>) -> Result<Vec<Robot>> {
	let pool = pool.clone();
	task::spawn_blocking(move || {
		let conn = pool.get().context("Failed to get database connection")?;

		let mut stmt = conn
			.prepare(
				"SELECT r.robot_id, r.name, r.specifications, r.manufacturer
				 FROM robots r"
			)
			.context("Failed to prepare statement")?;

		let robots_iter = stmt
			.query_map(params![], |row| {
				Ok(Robot {
					robot_id: row.get(0)?,
					name: row.get(1)?,
					specifications: row.get(2)?,
					manufacturer: row.get(3)?,
				})
			})
			.context("Failed to execute query")?;

		let mut robots = Vec::new();
		for robot in robots_iter {
			robots.push(robot.context("Failed to parse robot")?);
		}

		Ok(robots)
	})
		.await
		.context("Task join error")?
}

/// Adds a new robot to the database.
pub async fn add_robot(pool: Arc<SqlitePool>, form: RobotForm) -> Result<Robot> {
	let pool = pool.clone();
	let form_clone = form.clone();

	task::spawn_blocking(move || {
		let conn = pool.get().context("Failed to get database connection")?;

		conn.execute(
			"INSERT INTO robots (name, manufacturer, specifications) VALUES (?1, ?2, ?3)",
			params![
				form_clone.name,
				form_clone.manufacturer,
				form_clone.specifications,
			],
		).context("Failed to insert robot")?;

		let id = conn.last_insert_rowid();

		Ok(Robot {
			robot_id: Some(id as i32),
			name: form_clone.name,
			manufacturer: Some(form_clone.manufacturer),
			specifications: Some(form_clone.specifications),
		})
	})
		.await
		.context("Task join error")?
}

/// Updates an existing robot in the database.
pub async fn update_robot(pool: Arc<SqlitePool>, id: i32, form: RobotForm) -> Result<Robot> {
	let pool = pool.clone();
	let form_clone = form.clone();

	task::spawn_blocking(move || {
		let conn = pool.get().context("Failed to get database connection")?;

		let result = conn.execute(
			"UPDATE robots SET name = ?1, manufacturer = ?2, specifications = ?3
			 WHERE robot_id = ?4",
			params![
				form_clone.name,
				form_clone.manufacturer,
				form_clone.specifications,
				id
			],
		).context("Failed to update robot")?;

		if result != 1 {
			bail!("Robot not found");
		}

		Ok(Robot {
			robot_id: Some(id),
			name: form_clone.name,
			manufacturer: Some(form_clone.manufacturer),
			specifications: Some(form_clone.specifications),
		})
	})
		.await
		.context("Task join error")?
}

/// Deletes a robot from the database.
pub async fn delete_robot(pool: Arc<SqlitePool>, id: i32) -> Result<()> {
	let pool = pool.clone();
	task::spawn_blocking(move || {
		let conn = pool.get().context("Failed to get database connection")?;

		let result = conn
			.execute("DELETE FROM robots WHERE robot_id = ?1", params![id])
			.context("Failed to delete robot")?;

		if result != 1 {
			bail!("Robot not found");
		}

		Ok(())
	})
		.await
		.context("Task join error")?
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::db::connection;
	use tempfile::tempdir;

	async fn setup_test_db() -> Result<Arc<SqlitePool>> {
		let dir = tempdir()?;
		let db_path = dir.path().join("test.db");
		let pool = Arc::new(connection::establish_pool_with_path(db_path)?);

		let conn = pool.get()?;
		conn.execute_batch(
			"CREATE TABLE IF NOT EXISTS robots (
				robot_id INTEGER PRIMARY KEY,
				name TEXT NOT NULL,
				manufacturer TEXT,
				specifications TEXT
			);"
		)?;
		Ok(pool)
	}

	#[tokio::test]
	async fn test_robot_crud_operations() -> Result<()> {
		let pool = setup_test_db().await?;

		// Test Create
		let form = RobotForm {
			name: "TestBot".to_string(),
			manufacturer: "TestMfg".to_string(),
			specifications: "Test Specs".to_string(),
			software_versions: Vec::new(),
		};

		let robot = add_robot(pool.clone(), form.clone()).await?;
		assert_eq!(robot.name, "TestBot");

		// Test Read
		let robots = load_robots(pool.clone()).await?;
		assert_eq!(robots.len(), 1);
		assert_eq!(robots[0].name, "TestBot");

		// Test Update
		let mut updated_form = form.clone();
		updated_form.name = "UpdatedBot".to_string();
		let updated = update_robot(pool.clone(), robot.robot_id.unwrap(), updated_form).await?;
		assert_eq!(updated.name, "UpdatedBot");

		// Test Delete
		delete_robot(pool.clone(), robot.robot_id.unwrap()).await?;
		let robots = load_robots(pool.clone()).await?;
		assert!(robots.is_empty());

		Ok(())
	}
}
