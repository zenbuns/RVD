use iced::{Application, Command, Element, Settings, Size, Theme};
use std::sync::Arc;
use anyhow::{Result, Context};
use log::error;

use crate::db::connection::SqlitePool;
use super::state::AppState;
use super::types::Message;
use super::views::ViewRenderer;
use super::database::load_vulnerabilities;
use super::constants::{LOAD_PAGE_SIZE, DISPLAY_PAGE_SIZE};

pub struct VulnerabilityApp {
	state: AppState,
}

impl Application for VulnerabilityApp {
	type Executor = iced::executor::Default;
	type Message = Message;
	type Theme = Theme;
	type Flags = Arc<SqlitePool>;

	fn new(pool: Self::Flags) -> (Self, Command<Self::Message>) {
		let app = VulnerabilityApp {
			state: AppState::new(pool.clone()),
		};

		(
			app,
			Command::perform(
				load_vulnerabilities(
					pool,
					String::new(),
					0,
					LOAD_PAGE_SIZE,
					super::types::SortField::None,
					true,
					super::types::FilterSeverity::All,
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
				self.state.loading = false;
				match result {
					Ok((new_vulnerabilities, total_pages)) => {
						if self.state.last_loaded_page > 0 {
							self.state.vulnerabilities.extend(new_vulnerabilities);
						} else {
							self.state.vulnerabilities = new_vulnerabilities;
						}
						self.state.last_loaded_page += 1;
						self.state.total_pages = total_pages;
						self.state.update_displayed_vulnerabilities();
						self.state.error_message = None;
					}
					Err(err) => {
						error!("Failed to load vulnerabilities: {}", err);
						self.state.error_message = Some(err);
					}
				}
				Command::none()
			}
			Message::SearchQueryChanged(query) => {
				self.state.search_query = query;
				Command::none()
			}
			Message::PageChanged(page) => {
				if page < self.state.total_pages {
					self.state.current_page = page;
					self.state.selected_vulnerability = None;
					self.state.update_displayed_vulnerabilities();

					if page >= self.state.last_loaded_page * (LOAD_PAGE_SIZE / DISPLAY_PAGE_SIZE) {
						self.state.loading = true;
						let pool = self.state.pool.clone();
						let query = self.state.search_query.clone();
						Command::perform(
							load_vulnerabilities(
								pool,
								query,
								self.state.last_loaded_page + 1,
								LOAD_PAGE_SIZE,
								self.state.sort_field.clone(),
								self.state.sort_ascending,
								self.state.filter_severity.clone(),
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
				self.state.loading = true;
				self.state.selected_vulnerability = None;
				self.state.current_page = 0;
				self.state.last_loaded_page = 0;
				self.state.vulnerabilities.clear();
				self.state.displayed_vulnerabilities.clear();
				let pool = self.state.pool.clone();
				let query = self.state.search_query.clone();
				Command::perform(
					load_vulnerabilities(
						pool,
						query,
						0,
						LOAD_PAGE_SIZE,
						self.state.sort_field.clone(),
						self.state.sort_ascending,
						self.state.filter_severity.clone(),
					),
					Message::VulnerabilitiesLoaded,
				)
			}
			Message::SearchSubmitted => {
				self.state.current_page = 0;
				self.state.last_loaded_page = 0;
				self.state.loading = true;
				self.state.selected_vulnerability = None;
				self.state.vulnerabilities.clear();
				self.state.displayed_vulnerabilities.clear();
				let pool = self.state.pool.clone();
				let query = self.state.search_query.clone();
				Command::perform(
					load_vulnerabilities(
						pool,
						query,
						0,
						LOAD_PAGE_SIZE,
						self.state.sort_field.clone(),
						self.state.sort_ascending,
						self.state.filter_severity.clone(),
					),
					Message::VulnerabilitiesLoaded,
				)
			}
			Message::SortFieldSelected(field) => {
				self.state.sort_field = field;
				self.update(Message::RefreshData)
			}
			Message::ToggleSortOrder => {
				self.state.sort_ascending = !self.state.sort_ascending;
				self.update(Message::RefreshData)
			}
			Message::FilterSeverityChanged(severity) => {
				self.state.filter_severity = severity;
				self.update(Message::RefreshData)
			}
			Message::ToggleStatistics(value) => {
				self.state.show_statistics = value;
				Command::none()
			}
			Message::VulnerabilitySelected(idx) => {
				self.state.selected_vulnerability = Some(idx);
				Command::none()
			}
			Message::ClearSelection => {
				self.state.selected_vulnerability = None;
				Command::none()
			}
			Message::ScrollChanged(offset) => {
				self.state.scroll_offset = offset;
				if offset > super::constants::SCROLL_THRESHOLD
					&& self.state.current_page + 1 < self.state.total_pages {
					self.update(Message::PageChanged(self.state.current_page + 1))
				} else {
					Command::none()
				}
			},
			_ => todo!()
		}
	}

	fn view(&self) -> Element<Message> {
		if let Some(idx) = self.state.selected_vulnerability {
			if let Some(vuln) = self.state.displayed_vulnerabilities.get(idx) {
				return self.state.vulnerability_detail(vuln);
			}
		}

		let title = iced::widget::text("Robot Vulnerability Management System")
			.size(30);

		let content = iced::widget::column![
            title,
            self.state.control_panel(),
            self.state.search_bar(),
            if let Some(ref error) = self.state.error_message {
                iced::widget::text(error)
                    .style(iced::theme::Text::Color(iced::Color::from_rgb(1.0, 0.0, 0.0)))
                    .size(16)
            } else {
                iced::widget::text("")
            },
            if self.state.show_statistics {
                self.state.statistics()
            } else {
                iced::widget::text("").into()
            },
            self.state.vulnerability_list(),
            self.state.pagination_controls(),
        ]
			.spacing(20)
			.padding(20)
			.width(iced::Length::Fill);

		iced::widget::container(content)
			.width(iced::Length::Fill)
			.height(iced::Length::Fill)
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