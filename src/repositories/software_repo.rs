// src/repositories/software_repo.rs

use crate::db::connection::SqlitePool;
use crate::models::software::{SoftwareProduct, SoftwareVersion, AffectedSoftware};
use rusqlite::{params, Error as SqliteError};
use std::sync::Arc;
use anyhow::{Result, Context, anyhow};
use chrono::NaiveDateTime;
use tokio::task;
use log::{info, warn};

/// Convert i64 to i32 safely with context
fn to_i32(value: i64, context: &str) -> Result<i32> {
	i32::try_from(value).with_context(|| format!("Integer overflow for {}", context))
}

pub struct SoftwareRepository {
	pool: Arc<SqlitePool>,
}

impl SoftwareRepository {
	pub fn new(pool: Arc<SqlitePool>) -> Self {
		Self { pool }
	}

	pub async fn add_software_product(&self, product: SoftwareProduct) -> Result<i64> {
		let pool = self.pool.clone();

		task::spawn_blocking(move || {
			let mut conn = pool.get().context("Failed to get database connection")?;
			let tx = conn.transaction()?;

			let result = tx.execute(
				"INSERT INTO software_products (product_name, vendor, description)
				 VALUES (?1, ?2, ?3)",
				params![
					product.product_name,
					product.vendor,
					product.description,
				],
			).context("Failed to insert software product")?;

			if result != 1 {
				return Err(anyhow!("Failed to insert software product: unexpected row count"));
			}

			let id = tx.last_insert_rowid();
			tx.commit().context("Failed to commit transaction")?;

			Ok(id)
		})
			.await
			.context("Failed to execute database operation")?
	}

	pub async fn add_software_version(&self, version: SoftwareVersion) -> Result<i64> {
		let pool = self.pool.clone();

		task::spawn_blocking(move || {
			let mut conn = pool.get().context("Failed to get database connection")?;
			let tx = conn.transaction()?;

			let result = tx.execute(
				"INSERT INTO software_versions (product_id, version_number, release_date)
				 VALUES (?1, ?2, ?3)",
				params![
					version.product_id,
					version.version_number,
					version.release_date.map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string()),
				],
			).context("Failed to insert software version")?;

			if result != 1 {
				return Err(anyhow!("Failed to insert software version: unexpected row count"));
			}

			let id = tx.last_insert_rowid();
			tx.commit().context("Failed to commit transaction")?;

			Ok(id)
		})
			.await
			.context("Failed to execute database operation")?
	}

	pub async fn get_affected_software(&self, vulnerability_id: i32) -> Result<Vec<(AffectedSoftware, SoftwareProduct, SoftwareVersion)>> {
		let pool = self.pool.clone();

		task::spawn_blocking(move || -> Result<_> {
			let conn = pool.get().context("Failed to get database connection")?;

			let mut stmt = conn.prepare(
				"SELECT
					af.vulnerability_id,
					af.version_id,
					af.affected_version_pattern,
					af.fixed_in_version,
					af.detection_confidence,
					sp.product_id,
					sp.product_name,
					sp.vendor,
					sp.description,
					sv.version_number,
					sv.release_date
				FROM affected_software af
				JOIN software_versions sv ON af.version_id = sv.version_id
				JOIN software_products sp ON sv.product_id = sp.product_id
				WHERE af.vulnerability_id = ?"
			).context("Failed to prepare statement")?;

			let results = stmt.query_map([vulnerability_id], |row| -> rusqlite::Result<_> {
				let vuln_id: i64 = row.get(0)?;
				let version_id: i64 = row.get(1)?;
				let product_id: i64 = row.get(5)?;
				let release_date: Option<String> = row.get(10)?;

				Ok((
					AffectedSoftware {
						vulnerability_id: i32::try_from(vuln_id).map_err(|_| {
							SqliteError::InvalidQuery
						})?,
						version_id: i32::try_from(version_id).map_err(|_| {
							SqliteError::InvalidQuery
						})?,
						affected_version_pattern: row.get(2)?,
						fixed_in_version: row.get(3)?,
						detection_confidence: row.get(4)?,
					},
					SoftwareProduct {
						product_id: Some(i32::try_from(product_id).map_err(|_| {
							SqliteError::InvalidQuery
						})?),
						product_name: row.get(6)?,
						vendor: row.get(7)?,
						description: row.get(8)?,
					},
					SoftwareVersion {
						version_id: Some(i32::try_from(version_id).map_err(|_| {
							SqliteError::InvalidQuery
						})?),
						product_id: i32::try_from(product_id).map_err(|_| {
							SqliteError::InvalidQuery
						})?,
						version_number: row.get(9)?,
						release_date: release_date
							.and_then(|d| NaiveDateTime::parse_from_str(&d, "%Y-%m-%d %H:%M:%S").ok()),
					}
				))
			})?;

			results
				.collect::<rusqlite::Result<Vec<_>>>()
				.context("Failed to collect affected software")
		})
			.await
			.context("Failed to execute database operation")?
	}

	pub async fn search_software(&self, query: &str) -> Result<Vec<(SoftwareProduct, Vec<SoftwareVersion>)>> {
		let pool = self.pool.clone();
		let query = query.to_string();

		task::spawn_blocking(move || -> Result<_> {
			let conn = pool.get().context("Failed to get database connection")?;

			let mut stmt = conn.prepare(
				"SELECT
				sp.product_id,
				sp.product_name,
				sp.vendor,
				sp.description,
				sv.version_id,
				sv.version_number,
				sv.release_date
			FROM software_products sp
			LEFT JOIN software_versions sv ON sp.product_id = sv.product_id
			WHERE sp.product_name LIKE ?1 OR sp.vendor LIKE ?1
			ORDER BY sp.product_name, sv.release_date DESC"
			).context("Failed to prepare statement")?;

			let mut products = Vec::new();
			let mut current_product: Option<(SoftwareProduct, Vec<SoftwareVersion>)> = None;

			let rows = stmt.query_map([format!("%{}%", query)], |row| -> rusqlite::Result<(SoftwareProduct, Option<SoftwareVersion>)> {
				let product_id: i64 = row.get(0)?;
				let product_id_i32 = i32::try_from(product_id).map_err(|_| SqliteError::InvalidQuery)?;

				let product = SoftwareProduct {
					product_id: Some(product_id_i32),
					product_name: row.get(1)?,
					vendor: row.get(2)?,
					description: row.get(3)?,
				};

				let version = match row.get::<_, Option<i64>>(4)? {
					Some(version_id) => {
						let version_id_i32 = i32::try_from(version_id)
							.map_err(|_| SqliteError::InvalidQuery)?;
						let release_date: Option<String> = row.get(6)?;

						Some(SoftwareVersion {
							version_id: Some(version_id_i32),
							product_id: product_id_i32,
							version_number: row.get(5)?,
							release_date: release_date
								.and_then(|d| NaiveDateTime::parse_from_str(&d, "%Y-%m-%d %H:%M:%S").ok()),
						})
					},
					None => None,
				};

				Ok((product, version))
			})?;

			for row_result in rows {
				let (product, version) = row_result?;

				if let Some(ref mut current) = current_product {
					if current.0.product_id == product.product_id {
						if let Some(v) = version {
							current.1.push(v);
						}
						continue;
					}
					products.push(current.clone());
				}

				current_product = Some((product, version.map_or_else(Vec::new, |v| vec![v])));
			}

			if let Some(last) = current_product {
				products.push(last);
			}

			Ok(products)
		})
			.await
			.context("Failed to execute database operation")?
	}
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
		crate::db::schema::create_tables(&conn)?;

		Ok(pool)
	}

	#[tokio::test]
	async fn test_software_management() -> Result<()> {
		let pool = setup_test_db().await?;
		let repo = SoftwareRepository::new(pool);

		// Test product creation
		let product = SoftwareProduct {
			product_id: None,
			product_name: "Test Software".to_string(),
			vendor: "Test Vendor".to_string(),
			description: Some("Test Description".to_string()),
		};

		let product_id = repo.add_software_product(product).await?;
		assert!(product_id > 0);

		// Test version creation
		let version = SoftwareVersion {
			version_id: None,
			product_id: product_id as i32,
			version_number: "1.0.0".to_string(),
			release_date: Some(chrono::Utc::now().naive_utc()),
		};

		let version_id = repo.add_software_version(version).await?;
		assert!(version_id > 0);

		// Test search
		let results = repo.search_software("Test").await?;
		assert!(!results.is_empty());
		assert_eq!(results[0].0.product_name, "Test Software");
		assert!(!results[0].1.is_empty());

		Ok(())
	}
}