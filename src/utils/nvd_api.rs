use anyhow::{Context, Result};
use chrono::NaiveDate;
use log::{debug, error, info};
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use serde::Deserialize;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use crate::db::connection::SqlitePool;
use crate::models::vulnerability::Vulnerability;

const NVD_API_BASE_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const REQUEST_DELAY: Duration = Duration::from_millis(2000);

#[derive(Debug, Deserialize)]
struct NvdApiResponse {
	vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Debug, Deserialize)]
struct NvdVulnerability {
	cve: NvdCve,
}

#[derive(Debug, Deserialize)]
struct NvdCve {
	id: String,
	descriptions: Vec<NvdDescription>,
	metrics: Option<NvdMetrics>,
	published: String,
	lastModified: String,
}

#[derive(Debug, Deserialize)]
struct NvdDescription {
	lang: String,
	value: String,
}

#[derive(Debug, Deserialize)]
struct NvdMetrics {
	cvssMetrics: Vec<NvdCvssMetric>,
}

#[derive(Debug, Deserialize)]
struct NvdCvssMetric {
	source: String,
	score: Option<f64>,
	severity: Option<String>,
}

#[derive(Clone)]
pub struct NvdApiClient {
	client: reqwest::Client,
	pool: Arc<SqlitePool>,
}

impl NvdApiClient {
	pub fn new(pool: Arc<SqlitePool>) -> Result<Self> {
		let mut headers = HeaderMap::new();
		headers.insert(
			USER_AGENT,
			HeaderValue::from_static("Vulnerability-Management-System/1.0"),
		);

		let client = reqwest::Client::builder()
			.default_headers(headers)
			.build()
			.context("Failed to create HTTP client")?;

		Ok(Self { client, pool })
	}

	async fn fetch_nvd_data(&self, cve_id: &str) -> Result<NvdApiResponse> {
		let url = format!("{}?cveId={}", NVD_API_BASE_URL, cve_id);
		debug!("Fetching NVD data for {}", cve_id);

		let response = self.client
			.get(&url)
			.send()
			.await
			.context("Failed to send request to NVD API")?;

		if !response.status().is_success() {
			return Err(anyhow::anyhow!(
				"NVD API request failed with status: {}",
				response.status()
			));
		}

		let data = response
			.json::<NvdApiResponse>()
			.await
			.context("Failed to parse NVD API response")?;

		sleep(REQUEST_DELAY).await;
		Ok(data)
	}

	fn get_english_description(&self, descriptions: &[NvdDescription]) -> Option<String> {
		descriptions
			.iter()
			.find(|desc| desc.lang == "en")
			.map(|desc| desc.value.clone())
	}

	fn get_severity(&self, metrics: &Option<NvdMetrics>) -> Option<String> {
		metrics.as_ref().and_then(|m| {
			m.cvssMetrics.iter()
				.find(|metric| metric.severity.is_some())
				.and_then(|metric| metric.severity.clone())
				.map(|s| s.to_uppercase())
		})
	}

	async fn update_fields_if_unknown(&self, vuln: &Vulnerability) -> Result<bool> {
		// Check if any fields need updating
		let needs_update = vuln.description.as_ref().map_or(true, |d| d.trim().is_empty())
			|| vuln.severity.to_uppercase() == "UNKNOWN"
			|| vuln.published_date.is_none()
			|| vuln.impact.as_ref().map_or(true, |i| i.trim().is_empty())
			|| vuln.mitigation.as_ref().map_or(true, |m| m.trim().is_empty());

		if !needs_update {
			return Ok(false);
		}

		let nvd_data = self.fetch_nvd_data(&vuln.cve_id).await?;

		if let Some(vuln_data) = nvd_data.vulnerabilities.first() {
			// Only update fields that are unknown or empty
			let description = if vuln.description.as_ref().map_or(true, |d| d.trim().is_empty()) {
				self.get_english_description(&vuln_data.cve.descriptions)
			} else {
				vuln.description.clone()
			};

			let severity = if vuln.severity.to_uppercase() == "UNKNOWN" {
				self.get_severity(&vuln_data.cve.metrics)
					.unwrap_or_else(|| vuln.severity.clone())
			} else {
				vuln.severity.clone()
			};

			let published_date = if vuln.published_date.is_none() {
				NaiveDate::parse_from_str(&vuln_data.cve.published[..10], "%Y-%m-%d").ok()
			} else {
				vuln.published_date
			};

			// Use spawn_blocking for SQLite operations
			tokio::task::spawn_blocking({
				let pool = self.pool.clone();
				let cve_id = vuln.cve_id.clone();
				move || -> Result<()> {
					let conn = pool.get().context("Failed to get database connection")?;

					// Build dynamic update query based on which fields need updating
					let mut update_parts = Vec::new();
					let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

					if description.is_some() {
						update_parts.push("description = ?");
						params.push(Box::new(description.clone()));
					}

					if severity.to_uppercase() != "UNKNOWN" {
						update_parts.push("severity = ?");
						params.push(Box::new(severity.clone()));
					}

					if published_date.is_some() {
						update_parts.push("published_date = ?");
						params.push(Box::new(published_date.map(|d| d.to_string())));
					}

					if update_parts.is_empty() {
						return Ok(());
					}

					let query = format!(
						"UPDATE vulnerabilities SET {} WHERE cve_id = ?",
						update_parts.join(", ")
					);
					params.push(Box::new(cve_id));

					conn.execute(
						&query,
						rusqlite::params_from_iter(params.iter()),
					).context("Failed to update vulnerability record")?;

					Ok(())
				}
			})
				.await??;

			Ok(true)
		} else {
			Ok(false)
		}
	}

	pub async fn batch_update_vulnerabilities(&self, batch_size: usize) -> Result<usize> {
		let vulnerabilities = tokio::task::spawn_blocking({
			let pool = self.pool.clone();
			move || -> Result<Vec<Vulnerability>> {
				let conn = pool.get().context("Failed to get database connection")?;
				let mut stmt = conn.prepare(
					"SELECT vulnerability_id, cve_id, description, severity, impact, mitigation, published_date
					 FROM vulnerabilities
					 WHERE description IS NULL
						OR description = ''
						OR severity = 'UNKNOWN'
						OR published_date IS NULL
						OR impact IS NULL
						OR impact = ''
						OR mitigation IS NULL
						OR mitigation = ''
					 LIMIT ?"
				)?;

				let vulnerabilities = stmt.query_map([batch_size], |row| {
					Ok(Vulnerability {
						vulnerability_id: row.get(0)?,
						cve_id: row.get(1)?,
						description: row.get(2)?,
						severity: row.get(3)?,
						impact: row.get(4)?,
						mitigation: row.get(5)?,
						published_date: row.get::<_, Option<String>>(6)?
							.and_then(|d| NaiveDate::parse_from_str(&d, "%Y-%m-%d").ok()),
					})
				})?
					.collect::<Result<Vec<_>, _>>()?;

				Ok(vulnerabilities)
			}
		})
			.await??;

		let mut updated_count = 0;

		for vuln in vulnerabilities {
			match self.update_fields_if_unknown(&vuln).await {
				Ok(true) => {
					updated_count += 1;
					info!("Updated unknown fields for vulnerability: {}", vuln.cve_id);
				}
				Ok(false) => {
					debug!("No unknown fields to update for: {}", vuln.cve_id);
				}
				Err(e) => {
					error!("Failed to update unknown fields for {}: {}", vuln.cve_id, e);
				}
			}
		}

		Ok(updated_count)
	}
}