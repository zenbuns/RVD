use std::sync::Arc;
use crate::db::connection::SqlitePool;
use crate::models::vulnerability::Vulnerability;
use crate::models::robot::Robot;
use super::types::{SortField, FilterSeverity, RobotFilterType, RobotForm, Tab};
use super::constants::DISPLAY_PAGE_SIZE;

#[derive(Debug)]
pub struct AppState {
	// Database connection
	pub pool: Arc<SqlitePool>,

	// Vulnerability-related fields
	pub vulnerabilities: Vec<Vulnerability>,
	pub displayed_vulnerabilities: Vec<Vulnerability>,
	pub error_message: Option<String>,
	pub search_query: String,
	pub current_page: usize,
	pub total_pages: usize,
	pub loading: bool,
	pub sort_field: SortField,
	pub sort_ascending: bool,
	pub filter_severity: FilterSeverity,
	pub show_statistics: bool,
	pub selected_vulnerability: Option<usize>,
	pub scroll_offset: f32,
	pub last_loaded_page: usize,
	pub software_version_input: String,

	// Robot-related fields
	pub current_tab: Tab,
	pub robots: Vec<Robot>,
	pub robot_form: RobotForm,
	pub robot_filter: String,
	pub robot_filter_type: RobotFilterType,
	pub selected_robot: Option<usize>,
	pub editing_robot_id: Option<i32>,
	pub showing_robot_form: bool,
	pub filtered_robots: Vec<Robot>,
}

impl AppState {
	pub fn new(pool: Arc<SqlitePool>) -> Self {
		Self {
			// Database connection
			pool,

			// Vulnerability-related initialization
			vulnerabilities: Vec::new(),
			displayed_vulnerabilities: Vec::new(),
			error_message: None,
			search_query: String::new(),
			current_page: 0,
			total_pages: 0,
			loading: true,
			sort_field: SortField::None,
			sort_ascending: true,
			filter_severity: FilterSeverity::All,
			show_statistics: false,
			selected_vulnerability: None,
			scroll_offset: 0.0,
			last_loaded_page: 0,

			// Robot-related initialization
			current_tab: Tab::Vulnerabilities,
			robots: Vec::new(),
			filtered_robots: Vec::new(),
			robot_form: RobotForm {
				name: String::new(),
				manufacturer: String::new(),
				specifications: String::new(),
				software_versions: Vec::new(),
			},
			robot_filter: String::new(),
			robot_filter_type: RobotFilterType::All,
			selected_robot: None,
			editing_robot_id: None,
			showing_robot_form: false,
			software_version_input: String::new(),
		}
	}

	pub fn update_displayed_vulnerabilities(&mut self) {
		let start = self.current_page * DISPLAY_PAGE_SIZE;
		let end = (start + DISPLAY_PAGE_SIZE).min(self.vulnerabilities.len());
		self.displayed_vulnerabilities = self.vulnerabilities[start..end].to_vec();
		self.total_pages = (self.vulnerabilities.len() + DISPLAY_PAGE_SIZE - 1) / DISPLAY_PAGE_SIZE;
	}

	pub fn show_robot_form(&mut self) {
		self.showing_robot_form = true;
		self.clear_robot_form();
	}

	pub fn clear_robot_form(&mut self) {
		self.robot_form = RobotForm {
			name: String::new(),
			manufacturer: String::new(),
			specifications: String::new(),
			software_versions: Vec::new(),
		};
		self.editing_robot_id = None;
	}

	pub fn set_robot_form(&mut self, robot: &Robot) {
		self.robot_form = RobotForm {
			name: robot.name.clone(),
			manufacturer: robot.manufacturer.clone().unwrap_or_default(),
			specifications: robot.specifications.clone().unwrap_or_default(),
			software_versions: Vec::new(),
		};
		self.editing_robot_id = robot.robot_id;
		self.showing_robot_form = true;
	}

	pub fn filter_robots(&mut self) {
		self.filtered_robots = self.robots.clone();
		let filter = self.robot_filter.to_lowercase();

		if filter.is_empty() {
			return;
		}

		self.filtered_robots.retain(|robot| {
			match self.robot_filter_type {
				RobotFilterType::All => {
					robot.name.to_lowercase().contains(&filter) ||
						robot.manufacturer.as_ref().map_or(false, |m| m.to_lowercase().contains(&filter)) ||
						robot.specifications.as_ref().map_or(false, |s| s.to_lowercase().contains(&filter))
				},
				RobotFilterType::ByManufacturer => {
					robot.manufacturer
						.as_ref()
						.map_or(false, |m| m.to_lowercase().contains(&filter))
				},
				RobotFilterType::ByVulnerability => {
					// This would require joining with vulnerability data
					// For now, just search in specifications
					robot.specifications
						.as_ref()
						.map_or(false, |s| s.to_lowercase().contains(&filter))
				},
				RobotFilterType::BySoftware => {
					// This would require checking software_versions
					// For now, just search in specifications
					robot.specifications
						.as_ref()
						.map_or(false, |s| s.to_lowercase().contains(&filter))
				},
			}
		});
	}

	pub fn sort_robots(&mut self) {
		match self.sort_field {
			SortField::RobotName => {
				self.filtered_robots.sort_by(|a, b| {
					if self.sort_ascending {
						a.name.cmp(&b.name)
					} else {
						b.name.cmp(&a.name)
					}
				});
			},
			SortField::Manufacturer => {
				self.filtered_robots.sort_by(|a, b| {
					let a_manufacturer = a.manufacturer.as_deref().unwrap_or("");
					let b_manufacturer = b.manufacturer.as_deref().unwrap_or("");
					if self.sort_ascending {
						a_manufacturer.cmp(b_manufacturer)
					} else {
						b_manufacturer.cmp(a_manufacturer)
					}
				});
			},
			_ => (), // Other sort fields don't apply to robots
		}
	}

	pub fn clear_selection(&mut self) {
		self.selected_vulnerability = None;
		self.selected_robot = None;
		self.editing_robot_id = None;
		self.showing_robot_form = false;
	}

	pub fn handle_robot_form_submit(&mut self) -> bool {
		if self.robot_form.name.trim().is_empty() ||
			self.robot_form.manufacturer.trim().is_empty() ||
			self.robot_form.specifications.trim().is_empty() {
			self.error_message = Some("All fields are required".to_string());
			return false;
		}
		true
	}


	pub fn add_software_version(&mut self, version: String) {
		if !version.trim().is_empty() &&
			!self.robot_form.software_versions.contains(&version) {
			self.robot_form.software_versions.push(version);
		}
	}

	pub fn remove_software_version(&mut self, index: usize) {
		if index < self.robot_form.software_versions.len() {
			self.robot_form.software_versions.remove(index);
		}
	}

	pub fn update_error_message(&mut self, message: Option<String>) {
		self.error_message = message;
	}

	pub fn is_form_valid(&self) -> bool {
		!self.robot_form.name.trim().is_empty() &&
			!self.robot_form.manufacturer.trim().is_empty() &&
			!self.robot_form.specifications.trim().is_empty()
	}

	pub fn reset_robot_state(&mut self) {
		self.showing_robot_form = false;
		self.editing_robot_id = None;
		self.selected_robot = None;
		self.clear_robot_form();
		self.error_message = None;
	}

	pub fn handle_robot_edit(&mut self, robot_id: i32) -> bool {
		// Clone the robot data before modifying self
		let robot_data = self.robots
			.iter()
			.find(|r| r.robot_id == Some(robot_id))
			.cloned();

		if let Some(robot) = robot_data {
			self.set_robot_form(&robot);
			true
		} else {
			self.error_message = Some("Robot not found".to_string());
			false
		}
	}
}