use log::debug;
use std::sync::Arc;
use anyhow::{Result, Context};
use rusqlite::{Row as SqliteRow, Result as SqliteResult};
use chrono::NaiveDate;
use iced::{
    widget::{
        button, column, container, row, text_input, pick_list, Column, Row, Text, Rule,
        Scrollable, Space, Checkbox, scrollable,
    },
    Alignment, Application, Command, Element, Length, Settings, Size, Theme,
    theme, Rectangle,
};
use log::{error, info, warn};
use tokio::task;

use crate::db::connection::SqlitePool;
use crate::models::vulnerability::Vulnerability;

// Separate constants for display and loading
const DISPLAY_PAGE_SIZE: usize = 15;      // Number of items shown per page
const LOAD_PAGE_SIZE: usize = 324607;      // Number of items loaded from DB at once
const SCROLL_THRESHOLD: f32 = 0.8;        // When to trigger next page load

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SortField {
    CVE,
    Severity,
    Date,
    None,
}

impl std::fmt::Display for SortField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SortField::CVE => write!(f, "CVE ID"),
            SortField::Severity => write!(f, "Severity"),
            SortField::Date => write!(f, "Date"),
            SortField::None => write!(f, "No Sort"),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum FilterSeverity {
    All,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for FilterSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FilterSeverity::All => write!(f, "All Severities"),
            FilterSeverity::High => write!(f, "High"),
            FilterSeverity::Medium => write!(f, "Medium"),
            FilterSeverity::Low => write!(f, "Low"),
        }
    }
}

#[derive(Debug)]
pub struct VulnerabilityApp {
    pool: Arc<SqlitePool>,
    vulnerabilities: Vec<Vulnerability>,          // All loaded vulnerabilities
    displayed_vulnerabilities: Vec<Vulnerability>, // Currently displayed vulnerabilities
    error_message: Option<String>,
    search_query: String,
    current_page: usize,
    total_pages: usize,
    loading: bool,
    sort_field: SortField,
    sort_ascending: bool,
    filter_severity: FilterSeverity,
    show_statistics: bool,
    selected_vulnerability: Option<usize>,
    scroll_offset: f32,
    last_loaded_page: usize,

}

#[derive(Debug, Clone)]
pub enum Message {
    VulnerabilitiesLoaded(Result<(Vec<Vulnerability>, usize), String>),
    SearchQueryChanged(String),
    PageChanged(usize),
    RefreshData,
    SearchSubmitted,
    SortFieldSelected(SortField),
    ToggleSortOrder,
    FilterSeverityChanged(FilterSeverity),
    ToggleStatistics(bool),
    VulnerabilitySelected(usize),
    ClearSelection,
    ScrollChanged(f32),
}

fn format_severity(severity: &str) -> iced::Color {
    match severity.to_lowercase().as_str() {
        "high" => iced::Color::from_rgb(0.8, 0.0, 0.0),
        "medium" => iced::Color::from_rgb(0.8, 0.4, 0.0),
        "low" => iced::Color::from_rgb(0.0, 0.6, 0.0),
        _ => iced::Color::from_rgb(0.5, 0.5, 0.5),
    }
}

fn format_date(date: Option<NaiveDate>) -> String {
    date.map_or_else(
        || "Unknown".to_string(),
        |d| d.format("%Y-%m-%d").to_string()
    )
}

async fn load_vulnerabilities(
    pool: Arc<SqlitePool>,
    search_query: String,
    page: usize,
    page_size: usize,
    sort_field: SortField,
    sort_ascending: bool,
    filter_severity: FilterSeverity,
) -> Result<(Vec<Vulnerability>, usize), String> {
    task::spawn_blocking(move || {
        let conn = pool.get().map_err(|e| {
            error!("Database connection error: {}", e);
            format!("Failed to connect to database: {}", e)
        })?;

        let mut where_clauses = Vec::new();
        let mut params: Vec<String> = Vec::new();

        if !search_query.is_empty() {
            where_clauses.push("(cve_id LIKE ? OR description LIKE ?)");
            let pattern = format!("%{}%", search_query);
            params.push(pattern.clone());
            params.push(pattern);
        }

        match filter_severity {
            FilterSeverity::All => {}
            FilterSeverity::High => {
                where_clauses.push("LOWER(severity) = 'high'");
            }
            FilterSeverity::Medium => {
                where_clauses.push("LOWER(severity) = 'medium'");
            }
            FilterSeverity::Low => {
                where_clauses.push("LOWER(severity) = 'low'");
            }
        }

        let mut count_query = String::from("SELECT COUNT(*) FROM vulnerabilities");
        if !where_clauses.is_empty() {
            count_query.push_str(" WHERE ");
            count_query.push_str(&where_clauses.join(" AND "));
        }

        let param_values: Vec<&dyn rusqlite::ToSql> = params
            .iter()
            .map(|s| s as &dyn rusqlite::ToSql)
            .collect();

        let total_count: i64 = conn
            .query_row(&count_query, param_values.as_slice(), |row| row.get(0))
            .map_err(|e| {
                error!("Count query error: {}", e);
                format!("Failed to get total count: {}", e)
            })?;

        let mut query = String::from(
            "SELECT vulnerability_id, cve_id, description, severity, impact, mitigation, published_date 
             FROM vulnerabilities"
        );

        if !where_clauses.is_empty() {
            query.push_str(" WHERE ");
            query.push_str(&where_clauses.join(" AND "));
        }

        query.push_str(" ORDER BY ");
        query.push_str(match sort_field {
            SortField::CVE => "cve_id",
            SortField::Severity => "CASE severity 
                                  WHEN 'HIGH' THEN 1 
                                  WHEN 'MEDIUM' THEN 2 
                                  WHEN 'LOW' THEN 3 
                                  ELSE 4 END",
            SortField::Date => "COALESCE(published_date, '9999-12-31')",
            SortField::None => "vulnerability_id"
        });
        query.push_str(if sort_ascending { " ASC" } else { " DESC" });

        query.push_str(" LIMIT ? OFFSET ?");

        params.push(page_size.to_string());
        params.push((page * page_size).to_string());

        let param_values: Vec<&dyn rusqlite::ToSql> = params
            .iter()
            .map(|s| s as &dyn rusqlite::ToSql)
            .collect();

        info!("Executing query: {}", query);
        debug!("Parameters count: {}", param_values.len());

        let mut stmt = conn.prepare(&query).map_err(|e| {
            error!("Query preparation error: {}", e);
            format!("Failed to prepare query: {}", e)
        })?;

        let rows = stmt.query_map(param_values.as_slice(), |row| {
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
        }).map_err(|e| {
            error!("Query execution error: {}", e);
            format!("Failed to execute query: {}", e)
        })?;

        let results = rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|e| {
            error!("Row collection error: {}", e);
            format!("Failed to collect results: {}", e)
        })?;

        let total_pages = (total_count as usize + DISPLAY_PAGE_SIZE - 1) / DISPLAY_PAGE_SIZE;
        info!("Total records: {}, Total pages: {}", total_count, total_pages);

        Ok((results, total_pages))
    })
        .await
        .map_err(|e| format!("Task execution failed: {}", e))?
}
impl VulnerabilityApp {
    fn update_displayed_vulnerabilities(&mut self) {
        let start = self.current_page * DISPLAY_PAGE_SIZE;
        let end = (start + DISPLAY_PAGE_SIZE).min(self.vulnerabilities.len());
        self.displayed_vulnerabilities = self.vulnerabilities[start..end].to_vec();
    }

    fn handle_scroll(&mut self, offset: f32) -> Command<Message> {
        self.scroll_offset = offset;

        if offset > SCROLL_THRESHOLD && self.current_page + 1 < self.total_pages {
            self.current_page += 1;
            self.update_displayed_vulnerabilities();

            if self.current_page >= self.last_loaded_page * (LOAD_PAGE_SIZE / DISPLAY_PAGE_SIZE) {
                self.loading = true;
                let pool = self.pool.clone();
                let query = self.search_query.clone();
                Command::perform(
                    load_vulnerabilities(
                        pool,
                        query,
                        self.last_loaded_page + 1,
                        LOAD_PAGE_SIZE,
                        self.sort_field.clone(),
                        self.sort_ascending,
                        self.filter_severity.clone(),
                    ),
                    Message::VulnerabilitiesLoaded,
                )
            } else {
                Command::none()
            }
        } else {
            Command::none()
        }
    }


    fn search_bar(&self) -> Element<Message> {
        row![
            text_input("Search vulnerabilities...", &self.search_query)
                .on_input(Message::SearchQueryChanged)
                .on_submit(Message::SearchSubmitted)
                .padding(10)
                .width(Length::Fill),
            button(Text::new("Search").size(16))
                .on_press(Message::SearchSubmitted)
                .padding(10),
            button(Text::new("Refresh").size(16))
                .on_press(Message::RefreshData)
                .padding(10),
        ]
            .spacing(10)
            .align_items(Alignment::Center)
            .into()
    }

    fn get_statistics(&self) -> Element<Message> {
        let total = self.vulnerabilities.len();
        let high = self.vulnerabilities.iter()
            .filter(|v| v.severity.to_lowercase() == "high").count();
        let medium = self.vulnerabilities.iter()
            .filter(|v| v.severity.to_lowercase() == "medium").count();
        let low = self.vulnerabilities.iter()
            .filter(|v| v.severity.to_lowercase() == "low").count();

        container(
            column![
                Text::new("Vulnerability Statistics").size(24),
                Rule::horizontal(10),
                Text::new(format!("Total Vulnerabilities: {}", total)).size(16),
                row![
                    column![
                        Text::new("High Severity").style(theme::Text::Color(format_severity("high"))),
                        Text::new(format!("{} ({}%)", high, (high * 100) / total.max(1))),
                    ].spacing(5).width(Length::Fill),
                    column![
                        Text::new("Medium Severity").style(theme::Text::Color(format_severity("medium"))),
                        Text::new(format!("{} ({}%)", medium, (medium * 100) / total.max(1))),
                    ].spacing(5).width(Length::Fill),
                    column![
                        Text::new("Low Severity").style(theme::Text::Color(format_severity("low"))),
                        Text::new(format!("{} ({}%)", low, (low * 100) / total.max(1))),
                    ].spacing(5).width(Length::Fill),
                ].spacing(20),
            ]
                .spacing(10)
        )
            .padding(20)
            .style(theme::Container::Box)
            .into()
    }

    fn vulnerability_list(&self) -> Element<Message> {
        let content = if self.loading && self.displayed_vulnerabilities.is_empty() {
            column![Text::new("Loading...").size(20)]
        } else if self.displayed_vulnerabilities.is_empty() {
            column![Text::new("No vulnerabilities found").size(20)]
        } else {
            let mut list = Column::new().spacing(10);
            for (idx, vuln) in self.displayed_vulnerabilities.iter().enumerate() {
                list = list.push(self.vulnerability_card(vuln, idx));
            }
            list
        };

        scrollable(
            container(content)
                .width(Length::Fill)
                .padding(20)
        )
            .on_scroll(|viewport| {
                // Convert the RelativeOffset to f32
                let y_offset = viewport.relative_offset().y;
                Message::ScrollChanged(y_offset)
            })
            .height(Length::Fill)
            .into()
    }

    fn vulnerability_card<'a>(&self, vuln: &'a Vulnerability, idx: usize) -> Element<'a, Message> {
        let header = row![
            Text::new(&vuln.cve_id).size(18).width(Length::FillPortion(2)),
            Text::new(&vuln.severity)
                .size(16)
                .style(theme::Text::Color(format_severity(&vuln.severity)))
                .width(Length::FillPortion(1)),
            Text::new(format_date(vuln.published_date))
                .size(14)
                .width(Length::FillPortion(1)),
        ]
            .spacing(10)
            .align_items(Alignment::Center);

        let content = column![
            header,
            Text::new(vuln.description.as_deref().unwrap_or("No description available"))
                .size(14)
                .width(Length::Fill),
        ]
            .spacing(5);

        let is_selected = self.selected_vulnerability == Some(idx);

        button(
            container(content)
                .padding(10)
                .width(Length::Fill)
        )
            .style(if is_selected {
                theme::Button::Primary
            } else {
                theme::Button::Secondary
            })
            .on_press(Message::VulnerabilitySelected(idx))
            .width(Length::Fill)
            .into()
    }

    fn create_pagination_controls(&self) -> Element<Message> {
        let start_item = self.current_page * DISPLAY_PAGE_SIZE + 1;
        let end_item = ((self.current_page + 1) * DISPLAY_PAGE_SIZE)
            .min(self.vulnerabilities.len());
        let total_items = self.total_pages * DISPLAY_PAGE_SIZE;

        column![
            row![
                if self.current_page > 0 {
                    button(Text::new("Previous").size(16))
                        .on_press(Message::PageChanged(self.current_page.saturating_sub(1)))
                        .padding(10)
                } else {
                    button(Text::new("Previous").size(16))
                        .padding(10)
                        .style(theme::Button::Secondary)
                },
                Text::new(format!(
                    "Showing {}-{} of {} (Page {} of {})",
                    start_item,
                    end_item,
                    total_items,
                    self.current_page + 1,
                    self.total_pages
                ))
                .size(16),
                if (self.current_page + 1) * DISPLAY_PAGE_SIZE < self.vulnerabilities.len() {
                    button(Text::new("Next").size(16))
                        .on_press(Message::PageChanged(self.current_page + 1))
                        .padding(10)
                } else {
                    button(Text::new("Next").size(16))
                        .padding(10)
                        .style(theme::Button::Secondary)
                },
            ]
            .spacing(10)
            .align_items(Alignment::Center),

            // Quick navigation controls
            row![
                button(Text::new("First").size(14))
                    .on_press(Message::PageChanged(0))
                    .padding(5),
                button(Text::new("Last").size(14))
                    .on_press(Message::PageChanged(self.total_pages.saturating_sub(1)))
                    .padding(5),
            ]
            .spacing(5)
            .align_items(Alignment::Center),
        ]
            .spacing(5)
            .align_items(Alignment::Center)
            .into()
    }

    fn vulnerability_detail<'a>(&'a self, vuln: &'a Vulnerability) -> Element<'a, Message> {
        container(
            column![
                Row::new()
                    .push(Text::new(&vuln.cve_id).size(24))
                    .push(Space::with_width(Length::Fill))
                    .push(
                        button(Text::new("×").size(24))
                            .on_press(Message::ClearSelection)
                            .style(theme::Button::Destructive),
                    )
                    .align_items(Alignment::Center),
                Rule::horizontal(10),
                row![
                    Text::new("Severity: ").size(16),
                    Text::new(&vuln.severity)
                        .size(16)
                        .style(theme::Text::Color(format_severity(&vuln.severity))),
                ],
                Text::new(format!("Published: {}", format_date(vuln.published_date)))
                    .size(14),
                Rule::horizontal(10),
                Text::new("Description").size(18),
                Text::new(vuln.description.as_deref().unwrap_or("No description available"))
                    .size(16),
                Rule::horizontal(10),
                Text::new("Impact").size(18),
                Text::new(vuln.impact.as_deref().unwrap_or("No impact information available"))
                    .size(16),
                Rule::horizontal(10),
                Text::new("Mitigation").size(18),
                Text::new(vuln.mitigation.as_deref().unwrap_or("No mitigation steps available"))
                    .size(16),
            ]
                .spacing(20)
        )
            .padding(20)
            .style(theme::Container::Box)
            .into()
    }

    fn control_panel(&self) -> Element<Message> {
        container(
            row![
                pick_list(
                    vec![SortField::None, SortField::CVE, SortField::Severity, SortField::Date],
                    Some(self.sort_field.clone()),
                    Message::SortFieldSelected
                )
                .width(Length::Fixed(150.0))
                .padding(8),

                button(Text::new(if self.sort_ascending { "↑" } else { "↓" }).size(20))
                    .on_press(Message::ToggleSortOrder)
                    .padding(8),

                pick_list(
                    vec![
                        FilterSeverity::All,
                        FilterSeverity::High,
                        FilterSeverity::Medium,
                        FilterSeverity::Low
                    ],
                    Some(self.filter_severity.clone()),
                    Message::FilterSeverityChanged
                )
                .width(Length::Fixed(150.0))
                .padding(8),

                Checkbox::new("Show Statistics", self.show_statistics)
                    .on_toggle(Message::ToggleStatistics)
                    .spacing(8),
            ]
                .spacing(10)
                .align_items(Alignment::Center)
        )
            .style(theme::Container::Box)
            .padding(10)
            .into()
    }
}
impl Application for VulnerabilityApp {
    type Executor = iced::executor::Default;
    type Message = Message;
    type Theme = Theme;
    type Flags = Arc<SqlitePool>;

    fn new(pool: Self::Flags) -> (Self, Command<Self::Message>) {
        let app = VulnerabilityApp {
            pool: pool.clone(),
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
        };

        (
            app,
            Command::perform(
                load_vulnerabilities(
                    pool,
                    String::new(),
                    0,
                    LOAD_PAGE_SIZE,
                    SortField::None,
                    true,
                    FilterSeverity::All,
                ),
                Message::VulnerabilitiesLoaded,
            ),
        )
    }

    fn title(&self) -> String {
        String::from("Robot Vulnerability Management System")
    }

    fn update(&mut self, message: Message) -> Command<Message> {
        match message {
            Message::VulnerabilitiesLoaded(result) => {
                self.loading = false;
                match result {
                    Ok((new_vulnerabilities, total_pages)) => {
                        if self.last_loaded_page > 0 {
                            self.vulnerabilities.extend(new_vulnerabilities);
                        } else {
                            self.vulnerabilities = new_vulnerabilities;
                        }
                        self.last_loaded_page += 1;
                        self.total_pages = total_pages;
                        self.update_displayed_vulnerabilities();
                        self.error_message = None;
                    }
                    Err(err) => {
                        error!("Failed to load vulnerabilities: {}", err);
                        self.error_message = Some(err);
                    }
                }
                Command::none()
            }
            Message::SearchQueryChanged(query) => {
                self.search_query = query;
                Command::none()
            }
            Message::PageChanged(page) => {
                if page < self.total_pages {
                    self.current_page = page;
                    self.selected_vulnerability = None;
                    self.update_displayed_vulnerabilities();

                    if page >= self.last_loaded_page * (LOAD_PAGE_SIZE / DISPLAY_PAGE_SIZE) {
                        self.loading = true;
                        let pool = self.pool.clone();
                        let query = self.search_query.clone();
                        Command::perform(
                            load_vulnerabilities(
                                pool,
                                query,
                                self.last_loaded_page + 1,
                                LOAD_PAGE_SIZE,
                                self.sort_field.clone(),
                                self.sort_ascending,
                                self.filter_severity.clone(),
                            ),
                            Message::VulnerabilitiesLoaded,
                        )
                    } else {
                        Command::none()
                    }
                } else {
                    Command::none()
                }
            }
            Message::RefreshData => {
                self.loading = true;
                self.selected_vulnerability = None;
                self.current_page = 0;
                self.last_loaded_page = 0;
                self.vulnerabilities.clear();
                self.displayed_vulnerabilities.clear();
                let pool = self.pool.clone();
                let query = self.search_query.clone();
                Command::perform(
                    load_vulnerabilities(
                        pool,
                        query,
                        0,
                        LOAD_PAGE_SIZE,
                        self.sort_field.clone(),
                        self.sort_ascending,
                        self.filter_severity.clone(),
                    ),
                    Message::VulnerabilitiesLoaded,
                )
            }
            Message::SearchSubmitted => {
                self.current_page = 0;
                self.last_loaded_page = 0;
                self.loading = true;
                self.selected_vulnerability = None;
                self.vulnerabilities.clear();
                self.displayed_vulnerabilities.clear();
                let pool = self.pool.clone();
                let query = self.search_query.clone();
                Command::perform(
                    load_vulnerabilities(
                        pool,
                        query,
                        0,
                        LOAD_PAGE_SIZE,
                        self.sort_field.clone(),
                        self.sort_ascending,
                        self.filter_severity.clone(),
                    ),
                    Message::VulnerabilitiesLoaded,
                )
            }
            Message::SortFieldSelected(field) => {
                self.sort_field = field;
                self.update(Message::RefreshData)
            }
            Message::ToggleSortOrder => {
                self.sort_ascending = !self.sort_ascending;
                self.update(Message::RefreshData)
            }
            Message::FilterSeverityChanged(severity) => {
                self.filter_severity = severity;
                self.update(Message::RefreshData)
            }
            Message::ToggleStatistics(value) => {
                self.show_statistics = value;
                Command::none()
            }
            Message::VulnerabilitySelected(idx) => {
                self.selected_vulnerability = Some(idx);
                Command::none()
            }
            Message::ClearSelection => {
                self.selected_vulnerability = None;
                Command::none()
            }
            Message::ScrollChanged(offset) => self.handle_scroll(offset),
        }
    }

    fn view(&self) -> Element<Message> {
        if let Some(idx) = self.selected_vulnerability {
            if let Some(vuln) = self.displayed_vulnerabilities.get(idx) {
                return self.vulnerability_detail(vuln);
            }
        }

        let title = Text::new("Robot Vulnerability Management System")
            .size(30);

        let content = column![
            title,
            self.control_panel(),
            self.search_bar(),
            if let Some(ref error) = self.error_message {
                Text::new(error)
                    .style(theme::Text::Color(iced::Color::from_rgb(1.0, 0.0, 0.0)))
                    .size(16)
            } else {
                Text::new("")
            },
            if self.show_statistics {
                self.get_statistics()
            } else {
                Text::new("").into()
            },
            self.vulnerability_list(),
            self.create_pagination_controls(),
        ]
            .spacing(20)
            .padding(20)
            .width(Length::Fill);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x()
            .into()
    }
}

pub async fn run(pool: Arc<SqlitePool>) -> Result<()> {
    let mut settings = Settings::with_flags(pool);
    settings.window.size = Size::new(1024.0, 768.0);
    settings.window.min_size = Some(Size::new(800.0, 600.0));
    settings.window.resizable = true;

    VulnerabilityApp::run(settings)
        .context("Failed to run vulnerability management application")?;

    Ok(())
}