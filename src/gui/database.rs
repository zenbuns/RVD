use crate::db::connection::SqlitePool;
use crate::models::{robot::Robot, vulnerability::Vulnerability};
use crate::repositories::vulnerability_repo::VulnerabilityRepository;
use super::types::{FilterSeverity, RobotForm, SortField};
use std::sync::Arc;
use log::{error, info};
use tokio::task;
use anyhow::{Result, Context};
use rusqlite::params;

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

    // Apply additional filtering based on severity
    if !matches!(filter_severity, FilterSeverity::All) {
        let severity = match filter_severity {
            FilterSeverity::High => "high",
            FilterSeverity::Medium => "medium",
            FilterSeverity::Low => "low",
            FilterSeverity::All => unreachable!(),
        };
        vulnerabilities.retain(|v| v.severity.to_lowercase() == severity);
    }

    // Apply sorting based on the specified field
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
        // Ignore robot-specific sort fields when sorting vulnerabilities
        SortField::RobotName | SortField::Manufacturer => (),
    }

    Ok((vulnerabilities, total_pages))
}

/// Loads all robots from the database.
pub async fn load_robots(pool: Arc<SqlitePool>) -> Result<Vec<Robot>> {
    let pool = pool.clone();
    task::spawn_blocking(move || {
        let conn = pool.get().context("Failed to get database connection")?;

        let mut stmt = conn
            .prepare("SELECT robot_id, name, specifications, manufacturer FROM robots")
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
            params![form_clone.name, form_clone.manufacturer, form_clone.specifications],
        )
            .context("Failed to insert robot")?;

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
            "UPDATE robots SET name = ?1, manufacturer = ?2, specifications = ?3 WHERE robot_id = ?4",
            params![form_clone.name, form_clone.manufacturer, form_clone.specifications, id],
        )
            .context("Failed to update robot")?;

        if result != 1 {
            anyhow::bail!("Robot not found");
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
            anyhow::bail!("Robot not found");
        }

        Ok(())
    })
        .await
        .context("Task join error")?
}
