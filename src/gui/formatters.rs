use chrono::NaiveDate;
use iced::Color;

pub fn format_severity(severity: &str) -> Color {
    match severity.to_lowercase().as_str() {
        "high" => Color::from_rgb(0.9, 0.2, 0.2),    // Brighter red
        "medium" => Color::from_rgb(0.95, 0.5, 0.2), // Bright orange
        "low" => Color::from_rgb(0.2, 0.7, 0.2),     // Bright green
        _ => Color::from_rgb(0.6, 0.6, 0.6),         // Lighter gray
    }
}

pub fn format_severity_background(severity: &str) -> Color {
    match severity.to_lowercase().as_str() {
        "high" => Color::from_rgb(1.0, 0.9, 0.9),    // Light red background
        "medium" => Color::from_rgb(1.0, 0.95, 0.9), // Light orange background
        "low" => Color::from_rgb(0.9, 1.0, 0.9),     // Light green background
        _ => Color::from_rgb(0.95, 0.95, 0.95),      // Light gray background
    }
}

pub fn format_date(date: Option<NaiveDate>) -> String {
    date.map_or_else(
        || "Not Available".to_string(),
        |d| d.format("%Y-%m-%d").to_string()
    )
}

pub fn format_loading_message(progress: f32, operation_type: &str) -> String {
    format!("{} ({:.0}%)", operation_type, progress)
}