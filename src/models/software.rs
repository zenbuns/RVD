// src/models/software.rs

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareProduct {
	pub product_id: Option<i32>,
	pub product_name: String,
	pub vendor: String,
	pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareVersion {
	pub version_id: Option<i32>,
	pub product_id: i32,
	pub version_number: String,
	pub release_date: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedSoftware {
	pub vulnerability_id: i32,
	pub version_id: i32,
	pub affected_version_pattern: String,
	pub fixed_in_version: Option<String>,
	pub detection_confidence: f64,
}

impl SoftwareProduct {
	pub fn new(name: String, vendor: String) -> Self {
		Self {
			product_id: None,
			product_name: name,
			vendor,
			description: None,
		}
	}
}

impl SoftwareVersion {
	pub fn new(product_id: i32, version: String) -> Self {
		Self {
			version_id: None,
			product_id,
			version_number: version,
			release_date: Some(chrono::Utc::now().naive_utc()),
		}
	}
}

impl AffectedSoftware {
	pub fn new(vulnerability_id: i32, version_id: i32, pattern: String) -> Self {
		Self {
			vulnerability_id,
			version_id,
			affected_version_pattern: pattern,
			fixed_in_version: None,
			detection_confidence: 1.0,
		}
	}
}