use super::types::{Message, RobotForm, RobotFilterType, Tab};
use super::state::AppState;
use crate::models::robot::Robot;
use iced::{
    theme,
    widget::{
        button, column, container, pick_list, row, scrollable, text_input, Column,
        Rule, Space, Text,
    },
    Alignment, Element, Length,
};

pub trait RobotViewRenderer {
    fn robot_list(&self) -> Element<Message>;
    fn robot_card<'a>(&self, robot: &'a Robot, idx: usize) -> Element<'a, Message>;
    fn robot_form(&self) -> Element<Message>;
    fn robot_detail<'a>(&'a self, robot: &'a Robot) -> Element<'a, Message>;
    fn robot_control_panel(&self) -> Element<Message>;
    fn tab_selector(&self) -> Element<Message>;
}

impl RobotViewRenderer for AppState {
    fn tab_selector(&self) -> Element<Message> {
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

    fn robot_list(&self) -> Element<Message> {
        let content = if self.loading && self.robots.is_empty() {
            column![
                Space::with_height(Length::Fixed(40.0)),
                Text::new("Loading robots...")
                    .size(20)
                    .horizontal_alignment(iced::alignment::Horizontal::Center),
            ]
        } else if self.robots.is_empty() {
            column![
                Space::with_height(Length::Fixed(40.0)),
                Text::new("No robots found")
                    .size(20)
                    .horizontal_alignment(iced::alignment::Horizontal::Center),
                Space::with_height(Length::Fixed(20.0)),
                container(
                    button(Text::new("Add Robot").size(16))
                        .on_press(Message::AddRobotClicked)
                        .padding(12)
                        .style(theme::Button::Primary)
                )
                .center_x(),
            ]
        } else {
            let mut list = Column::new().spacing(12);
            for (idx, robot) in self.robots.iter().enumerate() {
                list = list.push(self.robot_card(robot, idx));
            }
            list
        };

        scrollable(
            container(content)
                .width(Length::Fill)
                .padding(20)
        )
            .height(Length::Fill)
            .into()
    }

    fn robot_card<'a>(&self, robot: &'a Robot, _idx: usize) -> Element<'a, Message> {
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

        let software_versions: Vec<Element<Message>> = self.robot_form.software_versions
            .iter()
            .enumerate()
            .map(|(idx, version)| {
                row![
                    Text::new(version).size(14),
                    button(Text::new("Remove"))
                        .on_press(Message::RobotFormSoftwareRemoved(idx))
                        .style(theme::Button::Destructive)
                        .padding(8),
                ]
                    .spacing(8)
                    .into()
            })
            .collect();

        container(
            column![
                Text::new(title).size(24),
                Space::with_height(Length::Fixed(20.0)),

                text_input("Robot Name", &self.robot_form.name)
                    .on_input(Message::RobotFormNameChanged)
                    .padding(12),

                text_input("Manufacturer", &self.robot_form.manufacturer)
                    .on_input(Message::RobotFormManufacturerChanged)
                    .padding(12),

                text_input("Specifications", &self.robot_form.specifications)
                    .on_input(Message::RobotFormSpecificationsChanged)
                    .padding(12),

                container(
                    column![
                        Text::new("Software Versions").size(16),
                        Column::with_children(software_versions).spacing(8),
                        text_input("Add Software Version", "")
                            .on_submit(Message::RobotFormSoftwareAdded(String::new()))
                            .padding(12),
                    ]
                )
                .style(theme::Container::Box)
                .padding(12),

                Space::with_height(Length::Fixed(20.0)),

                row![
                    button(Text::new("Cancel"))
                        .on_press(Message::RobotFormCancelled)
                        .style(theme::Button::Secondary)
                        .padding(12),

                    button(Text::new("Submit"))
                        .on_press(Message::RobotFormSubmitted)
                        .style(theme::Button::Primary)
                        .padding(12),
                ]
                .spacing(12),
            ]
                .spacing(12)
        )
            .style(theme::Container::Box)
            .padding(20)
            .width(Length::Fill)
            .into()
    }

    fn robot_detail<'a>(&'a self, robot: &'a Robot) -> Element<'a, Message> {
        let manufacturer = robot.manufacturer.as_deref().unwrap_or("Unknown");
        let specifications = robot.specifications.as_deref().unwrap_or("No specifications available");

        let software_versions: Vec<Element<Message>> = self.robot_form.software_versions
            .iter()
            .map(|version| {
                Text::new(version).size(14).into()
            })
            .collect();

        let software_section = if !software_versions.is_empty() {
            container(
                column![
                    Text::new("Software Versions").size(16),
                    Column::with_children(software_versions).spacing(8),
                ]
            )
                .style(theme::Container::Box)
                .padding(16)
        } else {
            container(
                Text::new("No software versions listed").size(14)
            )
                .style(theme::Container::Box)
                .padding(16)
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

                software_section,
            ]
                .spacing(16)
        )
            .style(theme::Container::Box)
            .padding(20)
            .into()
    }

    fn robot_control_panel(&self) -> Element<Message> {
        container(
            row![
                container(
                    pick_list(
                        vec![
                            RobotFilterType::All,
                            RobotFilterType::ByManufacturer,
                            RobotFilterType::ByVulnerability,
                            RobotFilterType::BySoftware,
                        ],
                        Some(self.robot_filter_type.clone()),
                        Message::RobotFilterTypeChanged
                    )
                    .width(Length::Fixed(200.0))
                    .padding(8)
                )
                .style(theme::Container::Box),

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
}