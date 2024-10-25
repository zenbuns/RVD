use std::sync::Arc;
use crate::db::connection::SqlitePool;
use crate::models::vulnerability::Vulnerability;
use super::types::{SortField, FilterSeverity};
use super::constants::DISPLAY_PAGE_SIZE;

#[derive(Debug)]
pub struct AppState {
    pub pool: Arc<SqlitePool>,
    pub vulnerabilities: Vec<Vulnerability>,       // Full dataset
    pub displayed_vulnerabilities: Vec<Vulnerability>, // Currently displayed page
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
}

impl AppState {
    pub fn new(pool: Arc<SqlitePool>) -> Self {
        Self {
            pool,
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
        }
    }

    pub fn update_displayed_vulnerabilities(&mut self) {
        let start = self.current_page * DISPLAY_PAGE_SIZE;
        let end = (start + DISPLAY_PAGE_SIZE).min(self.vulnerabilities.len());
        self.displayed_vulnerabilities = self.vulnerabilities[start..end].to_vec();
        self.total_pages = (self.vulnerabilities.len() + DISPLAY_PAGE_SIZE - 1) / DISPLAY_PAGE_SIZE;
    }
}