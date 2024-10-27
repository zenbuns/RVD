use super::types::{Message, RobotFilterType, Tab};
use super::state::AppState;
use crate::models::robot::Robot;
use iced::{
	theme,
	widget::{
		button, column, container, pick_list, row, scrollable, text_input, Column,
		Rule, Space, Text,
	},
	Alignment, Element, Length, Theme, Renderer,
};

pub trait RobotViewRenderer {
	fn robot_list(&self) -> Element<Message, Theme, Renderer>;
	fn robot_card<'a>(&'a self, robot: &'a Robot, idx: usize) -> Element<'a, Message, Theme, Renderer>;
	fn robot_form(&self) -> Element<Message, Theme, Renderer>;
	fn robot_detail<'a>(&'a self, robot: &'a Robot) -> Element<'a, Message, Theme, Renderer>;
	fn robot_control_panel(&self) -> Element<Message, Theme, Renderer>;
	fn tab_selector(&self) -> Element<Message, Theme, Renderer>;
}

impl RobotViewRenderer for AppState {
	fn robot_list(&self) -> Element<Message, Theme, Renderer> {
		if self.showing_robot_form {
			return self.robot_form();
		}

		let content: Element<Message, Theme, Renderer> = if self.loading && self.robots.is_empty() {
			Column::<Message, Theme, Renderer>::new()
				.push(Space::with_height(Length::Fixed(40.0)))
				.push(Text::new("Loading robots...")
					.size(20)
					.horizontal_alignment(iced::alignment::Horizontal::Center))
				.into()
		} else if self.robots.is_empty() {
			Column::<Message, Theme, Renderer>::new()
				.push(Space::with_height(Length::Fixed(40.0)))
				.push(Text::new("No robots found")
					.size(20)
					.horizontal_alignment(iced::alignment::Horizontal::Center))
				.push(Space::with_height(Length::Fixed(20.0)))
				.push(container(
					button(Text::new("Add Robot").size(16))
						.on_press(Message::AddRobotClicked)
						.padding(12)
						.style(theme::Button::Primary)
				)
					.center_x())
				.into()
		} else {
			let displayed_robots = self.get_displayed_robots();
			let mut list = Column::<Message, Theme, Renderer>::new().spacing(12);
			for (idx, robot) in displayed_robots.iter().enumerate() {
				list = list.push(self.robot_card(robot, idx));
			}
			list.into()
		};

		scrollable(
			container(content)
				.width(Length::Fill)
				.padding(20)
		)
			.height(Length::Fill)
			.into()
	}

	fn robot_card<'a>(&'a self, robot: &'a Robot, _idx: usize) -> Element<'a, Message, Theme, Renderer> {
		let name = &robot.name;
		let manufacturer = robot.manufacturer.as_deref().unwrap_or("Unknown Manufacturer");
		let specifications = robot.specifications.as_deref().unwrap_or("No specifications available");
		let robot_id = robot.robot_id.unwrap_or(0);

		container(
			column![
				row![
					column![
						Text::new(name)
							.size(18)
							.width(Length::Fill),
						Text::new(manufacturer)
							.size(14),
					]
					.width(Length::Fill),

					row![
						button(Text::new("Edit"))
							.on_press(Message::EditRobotClicked(robot_id))
							.style(theme::Button::Secondary)
							.padding(8),
						button(Text::new("Delete"))
							.on_press(Message::DeleteRobotClicked(robot_id))
							.style(theme::Button::Destructive)
							.padding(8),
					]
					.spacing(8),
				]
				.align_items(Alignment::Center),

				Text::new(specifications)
					.size(14)
					.width(Length::Fill),
			]
				.spacing(8)
		)
			.style(theme::Container::Box)
			.padding(12)
			.width(Length::Fill)
			.into()
	}

	fn robot_form(&self) -> Element<Message> {
		let title = if self.editing_robot_id.is_some() {
			"Edit Robot"
		} else {
			"Add New Robot"
		};

		let can_submit = !self.robot_form.name.is_empty()
			&& !self.robot_form.manufacturer.is_empty()
			&& !self.robot_form.specifications.is_empty();

		// Create the submit button conditionally
		let submit_button = if can_submit {
			button(
				Text::new(if self.editing_robot_id.is_some() {
					"Update Robot"
				} else {
					"Add Robot"
				}),
			)
				.on_press(Message::RobotFormSubmitted)
				.style(theme::Button::Primary)
				.padding(12)
		} else {
			button(
				Text::new(if self.editing_robot_id.is_some() {
					"Update Robot"
				} else {
					"Add Robot"
				}),
			)
				.style(theme::Button::Secondary)
				.padding(12)
		};

		// Left Column: Basic Information
		let basic_info = container(
			column![
			Text::new("Basic Information")
				.size(22)
				.width(Length::Fill),
			Space::with_height(Length::Fixed(10.0)),
			// Robot Name
			column![
				Text::new("Robot Name *")
					.size(16),
				text_input("Enter robot name", &self.robot_form.name)
					.on_input(Message::RobotFormNameChanged)
					.padding(10)
					.width(Length::Fill),
				if self.robot_form.name.is_empty() {
					Text::new("This field is required")
						.size(12)
						.style(theme::Text::Color(iced::Color::from_rgb8(200, 0, 0)))
				} else {
					Text::new("")
				},
			]
			.spacing(5),
			// Manufacturer
			column![
				Text::new("Manufacturer *")
					.size(16),
				text_input("Enter manufacturer", &self.robot_form.manufacturer)
					.on_input(Message::RobotFormManufacturerChanged)
					.padding(10)
					.width(Length::Fill),
				if self.robot_form.manufacturer.is_empty() {
					Text::new("This field is required")
						.size(12)
						.style(theme::Text::Color(iced::Color::from_rgb8(200, 0, 0)))
				} else {
					Text::new("")
				},
			]
			.spacing(5),
			// Specifications
			column![
				Text::new("Specifications *")
					.size(16),
				text_input("Enter specifications", &self.robot_form.specifications)
					.on_input(Message::RobotFormSpecificationsChanged)
					.padding(10)
					.width(Length::Fill),
				if self.robot_form.specifications.is_empty() {
					Text::new("This field is required")
						.size(12)
						.style(theme::Text::Color(iced::Color::from_rgb8(200, 0, 0)))
				} else {
					Text::new("")
				},
			]
			.spacing(5),
		]
				.spacing(15)
				.padding(10),
		)
			.style(theme::Container::Box)
			.width(Length::FillPortion(1));

		// Right Column: Software Versions
		let software_versions: Element<Message> = if !self.robot_form.software_versions.is_empty() {
			Column::with_children(
				self.robot_form
					.software_versions
					.iter()
					.enumerate()
					.map(|(idx, version)| {
						container(
							row![
							Text::new(version)
								.size(14)
								.width(Length::Fill),
							button(Text::new("Remove"))
								.on_press(Message::RobotFormSoftwareRemoved(idx))
								.style(theme::Button::Destructive)
								.padding(8),
						]
								.spacing(8)
								.align_items(Alignment::Center),
						)
							.style(theme::Container::Box)
							.padding(8)
							.into()
					})
					.collect::<Vec<Element<'_, Message>>>(),
			)
				.spacing(8)
				.into()
		} else {
			container(
				Text::new("No software versions added").size(14),
			)
				.style(theme::Container::Box)
				.padding(12)
				.width(Length::Fill)
				.into()
		};

		let software_versions_column = container(
			column![
			Text::new("Software Versions")
				.size(22)
				.width(Length::Fill),
			Space::with_height(Length::Fixed(10.0)),
			software_versions,
			row![
				text_input(
					"Enter software version",
					&self.software_version_input,
				)
				.on_input(Message::RobotFormSoftwareVersionInput)
				.on_submit(Message::RobotFormSoftwareVersionSubmit)
				.padding(10)
				.width(Length::Fill),
				button(Text::new("Add Version"))
					.on_press(Message::RobotFormSoftwareVersionSubmit)
					.style(theme::Button::Secondary)
					.padding(10),
			]
			.spacing(10),
		]
				.spacing(15)
				.padding(10),
		)
			.style(theme::Container::Box)
			.width(Length::FillPortion(1));

		// Combine both columns into a row
		let form_body = row![
		basic_info,
		Space::with_width(Length::Fixed(20.0)), // Add some space between columns
		software_versions_column,
	]
			.spacing(10)
			.width(Length::Fill);

		container(
			column![
			// Title and Close Button
			row![
				Text::new(title)
					.size(28)
					.width(Length::Fill),
				button(Text::new("Close").size(16))
					.on_press(Message::RobotFormCancelled)
					.style(theme::Button::Destructive)
					.padding(8),
			]
			.align_items(Alignment::Center),
			Rule::horizontal(1),
			Space::with_height(Length::Fixed(10.0)),
			// Form Body with Two Columns
			form_body,
			Space::with_height(Length::Fixed(10.0)),
			// Buttons
			row![
				button(Text::new("Cancel"))
					.on_press(Message::RobotFormCancelled)
					.style(theme::Button::Secondary)
					.padding(12),
				Space::with_width(Length::Fill),
				if !can_submit {
					Text::new("* Required fields must be filled")
						.size(14)
						.style(theme::Text::Color(iced::Color::from_rgb8(200, 0, 0)))
				} else {
					Text::new("")
				},
				submit_button,
			]
			.spacing(10)
			.align_items(Alignment::Center),
			if let Some(error) = &self.error_message {
				Text::new(error)
					.size(14)
					.style(theme::Text::Color(iced::Color::from_rgb8(200, 0, 0)))
			} else {
				Text::new("")
			},
		]
				.spacing(20)
				.padding(20)
				.max_width(800), // Adjust max_width as needed
		)
			.width(Length::Fill)
			//.center_x() // Remove this if centering causes clipping
			.into()
	}

	fn robot_detail<'a>(&'a self, robot: &'a Robot) -> Element<'a, Message, Theme, Renderer> {
		let manufacturer = robot.manufacturer.as_deref().unwrap_or("Unknown");
		let specifications = robot.specifications.as_deref().unwrap_or("No specifications available");

		// 1. Explicit type annotation for software_versions
		let software_versions: Element<'_, Message, Theme, Renderer> = if !self.robot_form.software_versions.is_empty() {
			Column::<Message, Theme, Renderer>::with_children(
				self.robot_form.software_versions
					.iter()
					.map(|version| Text::new(version).size(14).into())
					// 2. Explicit type for collect()
					.collect::<Vec<Element<'_, Message, Theme, Renderer>>>()
			)
				.spacing(8)
				.into()
		} else {
			Text::new("No software versions listed").size(14).into()
		};


		container(
			column![
				row![
					Text::new(&robot.name).size(28),
					Space::with_width(Length::Fill),
					button(Text::new("×").size(28))
						.on_press(Message::ClearSelection)
						.style(theme::Button::Destructive)
						.padding(8),
				],

				Rule::horizontal(10),

				container(
					column![
						Text::new("Manufacturer").size(16),
						Text::new(manufacturer).size(14),
					]
				)
				.style(theme::Container::Box)
				.padding(16),

				container(
					column![
						Text::new("Specifications").size(16),
						Text::new(specifications).size(14),
					]
				)
				.style(theme::Container::Box)
				.padding(16),

				container(
					column![
						Text::new("Software Versions").size(16),
						software_versions
					]
				)
				.style(theme::Container::Box)
				.padding(16),
			]
				.spacing(16)
		)
			.style(theme::Container::Box)
			.padding(20)
			.into()
	}


	fn robot_control_panel(&self) -> Element<Message, Theme, Renderer> {
		container(
			row![
				pick_list(
					vec![
						RobotFilterType::All,
						RobotFilterType::ByManufacturer,
						RobotFilterType::ByVulnerability,
						RobotFilterType::BySoftware,
					],
					Some(self.robot_filter_type.clone()),
					Message::RobotFilterTypeChanged,
				)
				.width(Length::Fixed(200.0))
				.padding(8),

				text_input("Filter...", &self.robot_filter)
					.on_input(Message::RobotFilterChanged)
					.padding(8)
					.width(Length::Fixed(200.0)),

				Space::with_width(Length::Fill),

				button(Text::new("Add Robot").size(16))
					.on_press(Message::AddRobotClicked)
					.style(theme::Button::Primary)
					.padding(12),
			]
				.spacing(12)
				.align_items(Alignment::Center)
		)
			.style(theme::Container::Box)
			.padding(15)
			.into()
	}

	fn tab_selector(&self) -> Element<Message, Theme, Renderer> {
		container(
			row![
				button(Text::new("Vulnerabilities").size(16))
					.style(if matches!(self.current_tab, Tab::Vulnerabilities) {
						theme::Button::Primary
					} else {
						theme::Button::Secondary
					})
					.on_press(Message::TabSelected(Tab::Vulnerabilities))
					.padding(12),

				button(Text::new("Robot Inventory").size(16))
					.style(if matches!(self.current_tab, Tab::RobotInventory) {
						theme::Button::Primary
					} else {
						theme::Button::Secondary
					})
					.on_press(Message::TabSelected(Tab::RobotInventory))
					.padding(12),
			]
				.spacing(12)
		)
			.style(theme::Container::Box)
			.padding(15)
			.into()
	}
}

// Add these helper functions if not already present
impl AppState {


	pub fn get_displayed_robots(&self) -> &Vec<Robot> {
		if self.filtered_robots.is_empty() {
			&self.robots
		} else {
			&self.filtered_robots
		}
	}
}