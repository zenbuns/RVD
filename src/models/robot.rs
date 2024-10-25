// src/models/robot.rs

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Robot {
	pub robot_id: Option<i32>,
	pub name: String,
	pub specifications: Option<String>,
	pub manufacturer: Option<String>,
}

impl Robot {
	pub fn new(name: String) -> Self {
		Self {
			robot_id: None,
			name,
			specifications: None,
			manufacturer: None,
		}
	}

	pub fn with_manufacturer(mut self, manufacturer: String) -> Self {
		self.manufacturer = Some(manufacturer);
		self
	}

	pub fn with_specifications(mut self, specifications: String) -> Self {
		self.specifications = Some(specifications);
		self
	}
}