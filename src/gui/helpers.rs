// src/gui/helpers.rs

use crate::db::connection::SqlitePool;
use crate::models::vulnerability::Vulnerability;
use std::sync::Arc;
use tokio::task;
use rusqlite::{params, Row, Result as SqliteResult};
use chrono::NaiveDate;

fn map_row(row: &Row) -> SqliteResult<Vulnerability> {
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
}

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