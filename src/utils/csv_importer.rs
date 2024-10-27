// src/db/importer.rs

use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use serde::Deserialize;
use csv::ReaderBuilder;
use tokio::task;
use anyhow::{Result, Context, Error};
use log::{info, warn};
use crate::models::vulnerability::Vulnerability;
use crate::db::connection::SqlitePool;
use std::sync::Arc;
use chrono::NaiveDate;
use rusqlite::Transaction;

/// The number of records to insert into the database in a single batch.
const BATCH_SIZE: usize = 1000;

/// Represents a record in the CSV file.
///
/// The struct fields are mapped to the actual CSV column headers using `serde`'s `rename` attribute.
#[derive(Debug, Deserialize)]
pub struct VulnerabilityCsvRecord {
	#[serde(rename = "Name")]
	pub cve_id: String,

	#[serde(rename = "Status")]
	pub severity: String,

	#[serde(rename = "Description")]
	pub description: String,

	#[serde(rename = "References")]
	pub references: Option<String>,

	#[serde(rename = "Phase")]
	pub published_date: Option<String>,

	#[serde(rename = "Votes")]
	pub impact: Option<String>,

	#[serde(rename = "Comments")]
	pub mitigation: Option<String>,
}

/// Imports vulnerabilities from a CSV file into the database.
///
/// # Arguments
///
/// * `file_path` - The path to the CSV file.
/// * `pool` - An `Arc`-wrapped `SqlitePool` for database connections.
///
/// # Returns
///
/// * `Result<usize>` - The number of successfully imported vulnerabilities.
pub async fn import_vulnerabilities_from_csv(
	file_path: String,
	pool: Arc<SqlitePool>,
) -> Result<usize> {
	task::spawn_blocking(move || -> Result<usize, Error> {
		let file = File::open(&file_path).context("Failed to open CSV file")?;
		let mut reader = BufReader::new(file);

		// Find the header line
		let header_line = find_header_line(&mut reader)?;
		info!("Header found at line {}", header_line + 1);

		// Seek back to the beginning after finding the header
		reader.seek(SeekFrom::Start(0))?;

		let mut rdr = ReaderBuilder::new()
			.trim(csv::Trim::All)
			.from_reader(reader);

		// Skip lines until the header is reached
		for _ in 0..header_line {
			let mut record = csv::StringRecord::new();
			if rdr.read_record(&mut record)? {
				info!("Skipping metadata line: {:?}", record);
			} else {
				break; // Reached EOF before finding header
			}
		}

		validate_csv_headers(&mut rdr)?;

		let mut successful_imports = 0;
		let mut batch = Vec::with_capacity(BATCH_SIZE);

		for (line_number, result) in rdr.deserialize::<VulnerabilityCsvRecord>().enumerate() {
			match process_csv_record(result, line_number + header_line + 2) {
				Ok(vuln) => {
					if !is_metadata_record(&vuln) {
						batch.push(vuln);
						if batch.len() >= BATCH_SIZE {
							successful_imports += insert_batch(&pool, &batch)?;
							batch.clear();
						}
					}
				}
				Err(e) => warn!("Skipping invalid record at line {}: {}", line_number + header_line + 2, e),
			}
		}

		if !batch.is_empty() {
			successful_imports += insert_batch(&pool, &batch)?;
		}

		info!(
			"Import completed. Successfully imported {} vulnerabilities.",
			successful_imports
		);
		Ok(successful_imports)
	})
		.await
		.context("Failed to run import task")?
}

/// Finds the line number where the CSV header starts.
///
/// # Arguments
///
/// * `reader` - A mutable reference to a `BufReader<File>`.
///
/// # Returns
///
/// * `Result<usize>` - The zero-based line number where the header is found.
fn find_header_line(reader: &mut BufReader<File>) -> Result<usize, Error> {
	let expected_headers = ["Name", "Status", "Description", "References", "Phase", "Votes", "Comments"];
	let mut line_number = 0;

	for line in reader.lines() {
		let line = line.context("Failed to read line from CSV")?;
		let trimmed = line.trim();

		// Split the line by commas and remove quotes
		let fields: Vec<&str> = trimmed
			.split(',')
			.map(|s| s.trim_matches('"').trim())
			.collect();

		// Check if the current line matches the expected headers (case-insensitive)
		if fields.len() >= expected_headers.len() && expected_headers.iter().zip(fields.iter()).all(|(e, f)| e.eq_ignore_ascii_case(f)) {
			return Ok(line_number);
		}

		line_number += 1;
	}

	Err(anyhow::anyhow!("Header row not found in CSV file"))
}

/// Validates that the CSV headers match the expected headers.
///
/// # Arguments
///
/// * `rdr` - A mutable reference to a `csv::Reader`.
///
/// # Returns
///
/// * `Result<()>` - Ok if headers are valid, Err otherwise.
fn validate_csv_headers(rdr: &mut csv::Reader<BufReader<File>>) -> Result<()> {
	let headers = rdr.headers().context("Failed to read CSV headers")?;
	let expected_headers = ["Name", "Status", "Description", "References", "Phase", "Votes", "Comments"];

	for (expected, actual) in expected_headers.iter().zip(headers.iter()) {
		if !expected.eq_ignore_ascii_case(actual) {
			return Err(anyhow::anyhow!(
				"Unexpected header. Expected '{}', found '{}'",
				expected,
				actual
			));
		}
	}
	Ok(())
}

/// Processes a single CSV record and converts it into a `Vulnerability` struct.
///
/// # Arguments
///
/// * `record_result` - The result of deserializing a CSV record.
/// * `line_number` - The line number in the CSV file.
///
/// # Returns
///
/// * `Result<Vulnerability>` - The processed vulnerability or an error.
fn process_csv_record(record_result: csv::Result<VulnerabilityCsvRecord>, line_number: usize) -> Result<Vulnerability, Error> {
	let record = record_result.context("Failed to deserialize CSV record")?;

	if !is_valid_cve_id(&record.cve_id) {
		return Err(anyhow::anyhow!("Invalid CVE ID format at line {}", line_number));
	}

	let published_date = record.published_date
		.as_ref()
		.and_then(|date_str| parse_date(date_str).ok());

	Ok(Vulnerability {
		vulnerability_id: None,
		cve_id: record.cve_id,
		description: non_empty_string(record.description),
		severity: parse_severity(&record.severity),
		impact: record.impact,
		mitigation: record.mitigation,
		published_date,
	})
}

/// Determines if a `Vulnerability` record is metadata.
///
/// # Arguments
///
/// * `vuln` - A reference to a `Vulnerability` struct.
///
/// # Returns
///
/// * `bool` - `true` if the record is metadata, `false` otherwise.
fn is_metadata_record(vuln: &Vulnerability) -> bool {
	vuln.description.is_none() && vuln.impact.is_none() && vuln.mitigation.is_none()
}

/// Converts a string to an `Option<String>`, returning `None` if the string is empty or whitespace.
///
/// # Arguments
///
/// * `s` - The input string.
///
/// # Returns
///
/// * `Option<String>` - `Some` with the trimmed string or `None`.
fn non_empty_string(s: String) -> Option<String> {
	let trimmed = s.trim();
	if trimmed.is_empty() { None } else { Some(trimmed.to_string()) }
}

/// Validates the format of a CVE ID.
///
/// # Arguments
///
/// * `cve_id` - The CVE ID string.
///
/// # Returns
///
/// * `bool` - `true` if valid, `false` otherwise.
fn is_valid_cve_id(cve_id: &str) -> bool {
	let parts: Vec<&str> = cve_id.split('-').collect();
	parts.len() == 3
		&& parts[0].eq_ignore_ascii_case("CVE")
		&& parts[1].len() == 4 && parts[1].chars().all(|c| c.is_digit(10))
		&& parts[2].len() >= 4 && parts[2].chars().all(|c| c.is_digit(10))
}

/// Parses the severity field into a standardized format.
///
/// # Arguments
///
/// * `raw_severity` - The raw severity string from the CSV.
///
/// # Returns
///
/// * `String` - The standardized severity.
fn parse_severity(raw_severity: &str) -> String {
	match raw_severity.to_lowercase().as_str() {
		"high" | "entry" => "High",
		"medium" | "candidate" => "Medium",
		"low" => "Low",
		_ => "Unknown",
	}.to_string()
}

/// Parses a date string into a `NaiveDate`.
///
/// # Arguments
///
/// * `date_str` - The date string from the CSV.
///
/// # Returns
///
/// * `Result<NaiveDate>` - The parsed date or an error.
fn parse_date(date_str: &str) -> Result<NaiveDate, Error> {
	// Handle dates with parentheses, e.g., "Modified (20051217)"
	if let Some(extracted) = date_str.split('(').nth(1) {
		let date_clean = extracted.trim_end_matches(')');
		NaiveDate::parse_from_str(date_clean, "%Y%m%d")
	} else {
		// Handle standard YYYY-MM-DD format
		NaiveDate::parse_from_str(date_str, "%Y-%m-%d")
	}.context("Date parsing failed")
}

/// Inserts a batch of vulnerabilities into the database.
///
/// # Arguments
///
/// * `pool` - An `Arc`-wrapped `SqlitePool`.
/// * `batch` - A slice of `Vulnerability` structs.
///
/// # Returns
///
/// * `Result<usize>` - The number of records inserted.
fn insert_batch(pool: &Arc<SqlitePool>, batch: &[Vulnerability]) -> Result<usize> {
	let mut connection = pool.get().context("Failed to get a connection from the pool")?;
	let transaction = connection.transaction().context("Failed to start database transaction")?;

	let inserted = insert_vulnerabilities(&transaction, batch).context("Failed to insert vulnerabilities")?;

	transaction.commit().context("Failed to commit transaction")?;
	Ok(inserted)
}

/// Inserts vulnerabilities into the database within a transaction.
///
/// # Arguments
///
/// * `transaction` - A reference to a `rusqlite::Transaction`.
/// * `vulnerabilities` - A slice of `Vulnerability` structs.
///
/// # Returns
///
/// * `Result<usize, rusqlite::Error>` - The number of records inserted or a database error.
fn insert_vulnerabilities(transaction: &Transaction, vulnerabilities: &[Vulnerability]) -> Result<usize, rusqlite::Error> {
	let mut stmt = transaction.prepare(
		"INSERT OR REPLACE INTO vulnerabilities (cve_id, description, severity, impact, mitigation, published_date)
		 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
	)?;

	let mut inserted = 0;
	for vuln in vulnerabilities {
		stmt.execute(rusqlite::params![
			vuln.cve_id,
			vuln.description,
			vuln.severity,
			vuln.impact,
			vuln.mitigation,
			vuln.published_date.map(|d| d.to_string()),
		])?;
		inserted += 1;
	}

	Ok(inserted)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_parse_severity() {
		assert_eq!(parse_severity("Entry"), "High");
		assert_eq!(parse_severity("Candidate"), "Medium");
		assert_eq!(parse_severity("Low"), "Low");
		assert_eq!(parse_severity("Other"), "Unknown");
	}

	#[test]
	fn test_parse_date() {
		assert_eq!(parse_date("Modified (20051217)").unwrap(), NaiveDate::from_ymd(2005, 12, 17));
		assert_eq!(parse_date("1999-06-21").unwrap(), NaiveDate::from_ymd(1999, 6, 21));
		assert!(parse_date("InvalidDate").is_err());
		assert!(parse_date("").is_err());
	}

	#[test]
	fn test_is_valid_cve_id() {
		assert!(is_valid_cve_id("CVE-1999-0001"));
		assert!(is_valid_cve_id("CVE-2023-12345"));
		assert!(!is_valid_cve_id("CVE-99-0001"));
		assert!(!is_valid_cve_id("CVE-2023-ABC"));
		assert!(!is_valid_cve_id("CWE-1999-0001"));
		assert!(!is_valid_cve_id("CVE-1999-00001"));
	}

	#[test]
	fn test_is_metadata_record() {
		let metadata_vuln = Vulnerability {
			vulnerability_id: None,
			cve_id: "CVE-2023-0001".to_string(),
			description: None,
			severity: "Unknown".to_string(),
			impact: None,
			mitigation: None,
			published_date: None,
		};
		assert!(is_metadata_record(&metadata_vuln));

		let real_vuln = Vulnerability {
			vulnerability_id: None,
			cve_id: "CVE-2023-0002".to_string(),
			description: Some("A real vulnerability".to_string()),
			severity: "High".to_string(),
			impact: Some("Severe impact".to_string()),
			mitigation: Some("Apply patch".to_string()),
			published_date: Some(NaiveDate::from_ymd(2023, 1, 1)),
		};
		assert!(!is_metadata_record(&real_vuln));
	}

	#[test]
	fn test_non_empty_string() {
		assert_eq!(non_empty_string("Hello".to_string()), Some("Hello".to_string()));
		assert_eq!(non_empty_string("  ".to_string()), None);
		assert_eq!(non_empty_string("".to_string()), None);
	}

	#[test]
	fn test_process_csv_record() {
		let valid_record = VulnerabilityCsvRecord {
			cve_id: "CVE-2023-0001".to_string(),
			severity: "High".to_string(),
			description: "A test vulnerability".to_string(),
			references: Some("https://example.com".to_string()),
			published_date: Some("2023-01-01".to_string()),
			impact: Some("Severe impact".to_string()),
			mitigation: Some("Apply patch".to_string()),
		};

		let result = process_csv_record(Ok(valid_record), 1);
		assert!(result.is_ok());
		let vuln = result.unwrap();
		assert_eq!(vuln.cve_id, "CVE-2023-0001");
		assert_eq!(vuln.severity, "High");
		assert_eq!(vuln.description, Some("A test vulnerability".to_string()));
		assert_eq!(vuln.impact, Some("Severe impact".to_string()));
		assert_eq!(vuln.mitigation, Some("Apply patch".to_string()));
		assert_eq!(vuln.published_date, Some(NaiveDate::from_ymd(2023, 1, 1)));

		let invalid_record = VulnerabilityCsvRecord {
			cve_id: "INVALID-ID".to_string(),
			severity: "High".to_string(),
			description: "An invalid record".to_string(),
			references: None,
			published_date: None,
			impact: None,
			mitigation: None,
		};

		let result = process_csv_record(Ok(invalid_record), 2);
		assert!(result.is_err());
	}

}
