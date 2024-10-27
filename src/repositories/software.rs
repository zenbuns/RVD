	// src/models/software.rs

	use chrono::NaiveDateTime;
	use serde::{Deserialize, Serialize};
	use crate::models::vulnerability::Vulnerability;

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

