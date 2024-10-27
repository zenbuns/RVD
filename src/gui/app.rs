use iced::{Application, Command, Element, Settings, Size, Theme};
use std::sync::Arc;
use anyhow::{Result, Context};
use log::error;

use crate::db::connection::SqlitePool;
use super::state::AppState;
use super::types::{Message, Tab};
use super::views::ViewRenderer;
use super::robot_view::RobotViewRenderer;
use super::database::{load_vulnerabilities, load_robots};
use super::constants::{LOAD_PAGE_SIZE, DISPLAY_PAGE_SIZE, SCROLL_THRESHOLD};

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

		// Convert error types properly in Command::perform callbacks
		(
			app,
			Command::batch(vec![
				Command::perform(
					load_vulnerabilities(
						pool.clone(),
						String::new(),
						0,
						LOAD_PAGE_SIZE,
						super::types::SortField::None,
						true,
						super::types::FilterSeverity::All,
					),
					|result| Message::VulnerabilitiesLoaded(result.map_err(|e| e.to_string())),
				),
				Command::perform(
					load_robots(pool),
					|result| Message::RobotsLoaded(result.map_err(|e| e.to_string())),
				),
			])
		)
	}

	fn title(&self) -> String {
		String::from("Robot Vulnerability Management System")
	}

	fn update(&mut self, message: Message) -> Command<Message> {
		match message {
			Message::TabSelected(tab) => {
				self.state.current_tab = tab;
				self.state.clear_selection();
				Command::none()
			}

			// Vulnerability-related messages with proper error handling
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
							|result| Message::VulnerabilitiesLoaded(result.map_err(|e| e.to_string())),
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
					|result| Message::VulnerabilitiesLoaded(result.map_err(|e| e.to_string())),
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
					|result| Message::VulnerabilitiesLoaded(result.map_err(|e| e.to_string())),
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
				self.state.clear_selection();
				Command::none()
			}

			Message::ScrollChanged(offset) => {
				self.state.scroll_offset = offset;
				if offset > SCROLL_THRESHOLD && self.state.current_page + 1 < self.state.total_pages {
					self.update(Message::PageChanged(self.state.current_page + 1))
				} else {
					Command::none()
				}
			}

			// Robot-related messages with proper error handling
			Message::RobotsLoaded(result) => {
				match result {
					Ok(robots) => {
						self.state.robots = robots;
						self.state.error_message = None;
					}
					Err(err) => {
						error!("Failed to load robots: {}", err);
						self.state.error_message = Some(err);
					}
				}
				Command::none()
			}

			Message::AddRobotClicked => {
				self.state.clear_robot_form();
				Command::none()
			}

			Message::EditRobotClicked(robot_id) => {
				// Solution to fix E0502 error: Limit the immutable borrow scope
				let robot_opt = self.state.robots.iter()
					.find(|r| r.robot_id == Some(robot_id))
					.cloned(); // Clone to avoid holding the immutable borrow

				if let Some(robot) = robot_opt {
					self.state.set_robot_form(&robot);
				}
				Command::none()
			}

			Message::DeleteRobotClicked(robot_id) => {
				Command::perform(
					super::database::delete_robot(self.state.pool.clone(), robot_id),
					|result| Message::RobotDeleted(result.map_err(|e| e.to_string())),
				)
			}

			Message::RobotFormNameChanged(name) => {
				self.state.robot_form.name = name;
				Command::none()
			}

			Message::RobotFormManufacturerChanged(manufacturer) => {
				self.state.robot_form.manufacturer = manufacturer;
				Command::none()
			}

			Message::RobotFormSpecificationsChanged(specifications) => {
				self.state.robot_form.specifications = specifications;
				Command::none()
			}

			Message::RobotFormSoftwareAdded(version) => {
				if !version.trim().is_empty() {
					self.state.robot_form.software_versions.push(version);
				}
				Command::none()
			}

			Message::RobotFormSoftwareRemoved(idx) => {
				if idx < self.state.robot_form.software_versions.len() {
					self.state.robot_form.software_versions.remove(idx);
				}
				Command::none()
			}

			Message::RobotFormSubmitted => {
				let form = self.state.robot_form.clone();
				if let Err(err) = super::types::validate_robot_form(&form) {
					self.state.error_message = Some(err.to_string());
					return Command::none();
				}

				let pool = self.state.pool.clone();
				if let Some(id) = self.state.editing_robot_id {
					Command::perform(
						super::database::update_robot(pool, id, form),
						|result| Message::RobotUpdated(result.map_err(|e| e.to_string())),
					)
				} else {
					Command::perform(
						super::database::add_robot(pool, form),
						|result| Message::RobotAdded(result.map_err(|e| e.to_string())),
					)
				}
			}

			Message::RobotFormCancelled => {
				self.state.clear_robot_form();
				Command::none()
			}

			Message::RobotFilterChanged(filter) => {
				self.state.robot_filter = filter;
				self.state.filter_robots();
				Command::none()
			}

			Message::RobotFilterTypeChanged(filter_type) => {
				self.state.robot_filter_type = filter_type;
				self.state.filter_robots();
				Command::none()
			}

			Message::RobotSelected(idx) => {
				self.state.selected_robot = Some(idx);
				Command::none()
			}

			Message::RobotAdded(result) => {
				match result {
					Ok(_) => {
						self.state.clear_robot_form();
						Command::perform(
							load_robots(self.state.pool.clone()),
							|result| Message::RobotsLoaded(result.map_err(|e| e.to_string())),
						)
					}
					Err(err) => {
						self.state.error_message = Some(err);
						Command::none()
					}
				}
			}

			Message::RobotUpdated(result) => {
				match result {
					Ok(_) => {
						self.state.clear_robot_form();
						Command::perform(
							load_robots(self.state.pool.clone()),
							|result| Message::RobotsLoaded(result.map_err(|e| e.to_string())),
						)
					}
					Err(err) => {
						self.state.error_message = Some(err);
						Command::none()
					}
				}
			}

			Message::RobotDeleted(result) => {
				match result {
					Ok(_) => {
						Command::perform(
							load_robots(self.state.pool.clone()),
							|result| Message::RobotsLoaded(result.map_err(|e| e.to_string())),
						)
					}
					Err(err) => {
						self.state.error_message = Some(err);
						Command::none()
					}
				}
			}

			// Error handling
			Message::ShowError(error) => {
				self.state.error_message = Some(error);
				Command::none()
			}

			Message::ClearError => {
				self.state.error_message = None;
				Command::none()
			}

			_ => Command::none(),
		}
	}

	fn view(&self) -> Element<Message> {
		let content = iced::widget::column![
            self.state.tab_selector(),
            match self.state.current_tab {
                Tab::Vulnerabilities => self.vulnerability_view(),
                Tab::RobotInventory => self.robot_view(),
            }
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

impl VulnerabilityApp {
	fn vulnerability_view(&self) -> Element<Message> {
		if let Some(idx) = self.state.selected_vulnerability {
			if let Some(vuln) = self.state.displayed_vulnerabilities.get(idx) {
				return self.state.vulnerability_detail(vuln);
			}
		}

		let title = iced::widget::text("Vulnerability Management")
			.size(30);

		iced::widget::column![
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
			.width(iced::Length::Fill)
			.into()
	}

	fn robot_view(&self) -> Element<Message> {
		if self.state.editing_robot_id.is_some() {
			return self.state.robot_form();
		}

		if let Some(idx) = self.state.selected_robot {
			if let Some(robot) = self.state.robots.get(idx) {
				return self.state.robot_detail(robot);
			}
		}

		let title = iced::widget::text("Robot Inventory")
			.size(30);

		iced::widget::column![
            title,
            self.state.robot_control_panel(),
            self.state.robot_list(),
        ]
			.spacing(20)
			.padding(20)
			.width(iced::Length::Fill)
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
