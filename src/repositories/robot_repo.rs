use crate::db::connection::SqlitePool;
use crate::models::robot::Robot;
use rusqlite::params;
use std::sync::Arc;
use anyhow::{Result, Context};
use tokio::task;
use log::{error, info};

pub async fn add_robot(pool: Arc<SqlitePool>, robot: Robot) -> Result<i64> {
	task::spawn_blocking(move || {
		let conn = pool.get().context("Failed to get database connection")?;
		let result = conn.execute(
			"INSERT INTO robots (name, specifications, manufacturer) VALUES (?1, ?2, ?3)",
			params![
				robot.name,
				robot.specifications,
				robot.manufacturer,
			],
		).context("Failed to execute INSERT query")?;

		if result == 0 {
			anyhow::bail!("Failed to insert robot");
		}

		Ok(conn.last_insert_rowid())
	})
		.await
		.context("Failed to execute database operation")?
}

pub async fn get_all_robots(pool: Arc<SqlitePool>) -> Result<Vec<Robot>> {
	task::spawn_blocking(move || {
		let conn = pool.get().context("Failed to get database connection")?;
		let mut stmt = conn.prepare("SELECT robot_id, name, specifications, manufacturer FROM robots")
			.context("Failed to prepare SELECT query")?;

		let robot_iter = stmt.query_map([], |row| {
			Ok(Robot {
				robot_id: Some(row.get(0)?),
				name: row.get(1)?,
				specifications: row.get(2)?,
				manufacturer: row.get(3)?,
			})
		})
			.context("Failed to execute SELECT query")?;

		robot_iter
			.collect::<rusqlite::Result<Vec<_>>>()
			.context("Failed to collect robots")
	})
		.await
		.context("Failed to execute database operation")?
}

pub async fn get_robot_by_id(pool: Arc<SqlitePool>, id: i64) -> Result<Robot> {
	task::spawn_blocking(move || {
		let conn = pool.get().context("Failed to get database connection")?;
		conn.query_row(
			"SELECT robot_id, name, specifications, manufacturer FROM robots WHERE robot_id = ?1",
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

pub async fn delete_robot(pool: Arc<SqlitePool>, id: i64) -> Result<()> {
	task::spawn_blocking(move || {
		let conn = pool.get().context("Failed to get database connection")?;
		let result = conn.execute(
			"DELETE FROM robots WHERE robot_id = ?1",
			params![id],
		).context("Failed to execute DELETE query")?;

		if result == 0 {
			anyhow::bail!("Robot not found");
		}

		Ok(())
	})
		.await
		.context("Failed to execute database operation")?
}