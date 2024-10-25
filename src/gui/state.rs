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

    // Robot-related fields
    pub current_tab: Tab,
    pub robots: Vec<Robot>,
    pub robot_form: RobotForm,
    pub robot_filter: String,
    pub robot_filter_type: RobotFilterType,
    pub selected_robot: Option<usize>,
    pub editing_robot_id: Option<i32>,
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
        }
    }

    pub fn update_displayed_vulnerabilities(&mut self) {
        let start = self.current_page * DISPLAY_PAGE_SIZE;
        let end = (start + DISPLAY_PAGE_SIZE).min(self.vulnerabilities.len());
        self.displayed_vulnerabilities = self.vulnerabilities[start..end].to_vec();
        self.total_pages = (self.vulnerabilities.len() + DISPLAY_PAGE_SIZE - 1) / DISPLAY_PAGE_SIZE;
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
            software_versions: Vec::new(), // You'll need to load this from somewhere
        };
        self.editing_robot_id = robot.robot_id;
    }

    pub fn filter_robots(&mut self) {
        // This is a placeholder - implement actual filtering logic based on
        // self.robot_filter and self.robot_filter_type
        match self.robot_filter_type {
            RobotFilterType::All => {
                // No filtering needed
            },
            RobotFilterType::ByManufacturer => {
                let filter = self.robot_filter.to_lowercase();
                self.robots.retain(|robot| {
                    robot.manufacturer
                        .as_ref()
                        .map(|m| m.to_lowercase().contains(&filter))
                        .unwrap_or(false)
                });
            },
            RobotFilterType::ByVulnerability => {
                // Implement vulnerability-based filtering
            },
            RobotFilterType::BySoftware => {
                // Implement software version-based filtering
            },
        }
    }

    pub fn clear_selection(&mut self) {
        self.selected_vulnerability = None;
        self.selected_robot = None;
        self.editing_robot_id = None;
    }
}