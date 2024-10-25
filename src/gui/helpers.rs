// src/gui/helpers.rs

use crate::db::connection::SqlitePool;
use crate::models::vulnerability::Vulnerability;
use std::sync::Arc;
use tokio::task;
use rusqlite::{params, Row, Result as SqliteResult};
use chrono::NaiveDate;


pub fn format_severity(severity: &str) -> iced::Color {
	match severity.to_lowercase().as_str() {
		"high" => iced::Color::from_rgb(1.0, 0.0, 0.0),  // Red
		"medium" => iced::Color::from_rgb(1.0, 0.5, 0.0), // Orange
		"low" => iced::Color::from_rgb(0.0, 0.7, 0.0),    // Green
		_ => iced::Color::from_rgb(0.5, 0.5, 0.5),        // Gray
	}
}

pub fn format_date(date: Option<NaiveDate>) -> String {
	date.map_or_else(
		|| "Unknown".to_string(),
		|d| d.format("%Y-%m-%d").to_string()
	)
}