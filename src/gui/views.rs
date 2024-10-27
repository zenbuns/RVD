use super::constants::DISPLAY_PAGE_SIZE;
use super::formatters::{format_date, format_severity};
use super::state::AppState;
use super::types::Message;
use crate::models::vulnerability::Vulnerability;
use iced::{
    theme,
    widget::{
        button, column, container, pick_list, row, scrollable, text_input, Checkbox, Column, Row,
        Rule, Space, Text,
    },
    Alignment, Element, Length,
};

pub trait ViewRenderer {
    fn search_bar(&self) -> Element<Message>;
    fn statistics(&self) -> Element<Message>;
    fn vulnerability_list(&self) -> Element<Message>;
    fn vulnerability_card<'a>(&self, vuln: &'a Vulnerability, idx: usize) -> Element<'a, Message>;
    fn pagination_controls(&self) -> Element<Message>;
    fn vulnerability_detail<'a>(&'a self, vuln: &'a Vulnerability) -> Element<'a, Message>;
    fn control_panel(&self) -> Element<Message>;
}

impl ViewRenderer for AppState {
    fn search_bar(&self) -> Element<Message> {
        container(
            row![
                text_input("Search by CVE ID, description, or severity...", &self.search_query)
                    .on_input(Message::SearchQueryChanged)
                    .on_submit(Message::SearchSubmitted)
                    .padding(12)
                    .width(Length::Fill),
                button(
                    row![
                        Text::new("Search").size(16).horizontal_alignment(iced::alignment::Horizontal::Center),
                    ].spacing(8)
                )
                    .style(theme::Button::Primary)
                    .on_press(Message::SearchSubmitted)
                    .padding(12),
                button(
                    row![
                        Text::new("Refresh").size(16).horizontal_alignment(iced::alignment::Horizontal::Center),
                    ].spacing(8)
                )
                    .on_press(Message::RefreshData)
                    .padding(12),
            ]
                .spacing(12)
                .align_items(Alignment::Center)
        )
            .style(theme::Container::Box)
            .padding(15)
            .into()
    }

    fn statistics(&self) -> Element<Message> {
        let total = self.vulnerabilities.len();
        let high = self.vulnerabilities.iter()
            .filter(|v| v.severity.to_lowercase() == "high").count();
        let medium = self.vulnerabilities.iter()
            .filter(|v| v.severity.to_lowercase() == "medium").count();
        let low = self.vulnerabilities.iter()
            .filter(|v| v.severity.to_lowercase() == "low").count();

        container(
            column![
                Text::new("Vulnerability Overview").size(28).horizontal_alignment(iced::alignment::Horizontal::Center),
                Space::with_height(Length::Fixed(20.0)),
                Rule::horizontal(10),
                Space::with_height(Length::Fixed(20.0)),
                Text::new(format!("Total Vulnerabilities: {}", total))
                    .size(18)
                    .horizontal_alignment(iced::alignment::Horizontal::Center),
                Space::with_height(Length::Fixed(20.0)),
                row![
                    container(
                        column![
                            Text::new("High Severity")
                                .style(theme::Text::Color(format_severity("high")))
                                .size(16),
                            Text::new(format!("{} ({}%)", high, (high * 100) / total.max(1)))
                                .size(24)
                                .horizontal_alignment(iced::alignment::Horizontal::Center),
                        ].spacing(8)
                    )
                    .style(theme::Container::Box)
                    .padding(15)
                    .width(Length::Fill),
                    container(
                        column![
                            Text::new("Medium Severity")
                                .style(theme::Text::Color(format_severity("medium")))
                                .size(16),
                            Text::new(format!("{} ({}%)", medium, (medium * 100) / total.max(1)))
                                .size(24)
                                .horizontal_alignment(iced::alignment::Horizontal::Center),
                        ].spacing(8)
                    )
                    .style(theme::Container::Box)
                    .padding(15)
                    .width(Length::Fill),
                    container(
                        column![
                            Text::new("Low Severity")
                                .style(theme::Text::Color(format_severity("low")))
                                .size(16),
                            Text::new(format!("{} ({}%)", low, (low * 100) / total.max(1)))
                                .size(24)
                                .horizontal_alignment(iced::alignment::Horizontal::Center),
                        ].spacing(8)
                    )
                    .style(theme::Container::Box)
                    .padding(15)
                    .width(Length::Fill),
                ].spacing(15),
            ]
        )
            .padding(20)
            .style(theme::Container::Box)
            .into()
    }

    fn vulnerability_list(&self) -> Element<Message> {
        let content = if self.loading && self.displayed_vulnerabilities.is_empty() {
            column![
                Space::with_height(Length::Fixed(40.0)),
                Text::new("Loading vulnerabilities...")
                    .size(20)
                    .horizontal_alignment(iced::alignment::Horizontal::Center),
            ]
        } else if self.displayed_vulnerabilities.is_empty() {
            column![
                Space::with_height(Length::Fixed(40.0)),
                Text::new("No vulnerabilities found")
                    .size(20)
                    .horizontal_alignment(iced::alignment::Horizontal::Center),
            ]
        } else {
            let mut list = Column::new().spacing(12);
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
                Message::ScrollChanged(viewport.relative_offset().y)
            })
            .height(Length::Fill)
            .into()
    }

    fn vulnerability_card<'a>(&self, vuln: &'a Vulnerability, idx: usize) -> Element<'a, Message> {
        let header = row![
        column![
            Text::new(&vuln.cve_id)
                .size(18)
                .width(Length::Fill),
            Space::with_height(Length::Fixed(4.0)),
            Text::new(format_date(vuln.published_date))
                .size(12),
        ].width(Length::FillPortion(3)),

        container(
            Text::new(&vuln.severity)
                .size(14)
                .style(theme::Text::Color(format_severity(&vuln.severity)))
        )
        .padding(8)
        .style(theme::Container::Box)
        .width(Length::FillPortion(1)),
    ]
            .spacing(12)
            .align_items(Alignment::Center);

        let content = column![
        header,
        Space::with_height(Length::Fixed(8.0)),
        Text::new(vuln.description.as_deref().unwrap_or("No description available"))
            .size(14)
            .width(Length::Fill),
    ]
            .spacing(8);

        let is_selected = self.selected_vulnerability == Some(idx);

        button(
            container(content)
                .padding(12)
                .width(Length::Fill)
                .style(if is_selected {
                    theme::Container::Box
                } else {
                    theme::Container::Transparent
                })
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


    fn pagination_controls(&self) -> Element<Message> {
        let start_item = self.current_page * DISPLAY_PAGE_SIZE + 1;
        let end_item = ((self.current_page + 1) * DISPLAY_PAGE_SIZE)
            .min(self.vulnerabilities.len());
        let total_items = self.total_pages * DISPLAY_PAGE_SIZE;

        container(
            column![
            // Main pagination row
            row![
                // Left side buttons group
                row![
                    button(
                        Text::new("«").size(16)
                    )
                    .style(if self.current_page > 0 {
                        theme::Button::Primary
                    } else {
                        theme::Button::Secondary
                    })
                    .on_press_maybe(if self.current_page > 0 {
                        Some(Message::PageChanged(0))
                    } else {
                        None
                    })
                    .padding(12),

                    button(
                        Text::new("‹").size(16)
                    )
                    .style(if self.current_page > 0 {
                        theme::Button::Primary
                    } else {
                        theme::Button::Secondary
                    })
                    .on_press_maybe(if self.current_page > 0 {
                        Some(Message::PageChanged(self.current_page.saturating_sub(1)))
                    } else {
                        None
                    })
                    .padding(12),
                ]
                .spacing(8),

                // Center text with page information
                container(
                    Text::new(format!(
                        "Page {} of {} ({} items)",
                        self.current_page + 1,
                        self.total_pages,
                        total_items
                    ))
                    .size(14)
                    .horizontal_alignment(iced::alignment::Horizontal::Center)
                )
                .width(Length::Fill)
                .center_x(),

                // Right side buttons group
                row![
                    button(
                        Text::new("›").size(16)
                    )
                    .style(if (self.current_page + 1) * DISPLAY_PAGE_SIZE < self.vulnerabilities.len() {
                        theme::Button::Primary
                    } else {
                        theme::Button::Secondary
                    })
                    .on_press_maybe(if (self.current_page + 1) * DISPLAY_PAGE_SIZE < self.vulnerabilities.len() {
                        Some(Message::PageChanged(self.current_page + 1))
                    } else {
                        None
                    })
                    .padding(12),

                    button(
                        Text::new("»").size(16)
                    )
                    .style(if (self.current_page + 1) * DISPLAY_PAGE_SIZE < self.vulnerabilities.len() {
                        theme::Button::Primary
                    } else {
                        theme::Button::Secondary
                    })
                    .on_press_maybe(if (self.current_page + 1) * DISPLAY_PAGE_SIZE < self.vulnerabilities.len() {
                        Some(Message::PageChanged(self.total_pages.saturating_sub(1)))
                    } else {
                        None
                    })
                    .padding(12),
                ]
                .spacing(8),
            ]
            .spacing(20)
            .align_items(Alignment::Center),

            // Item range indicator
            container(
                Text::new(format!(
                    "Showing items {}-{}",
                    start_item,
                    end_item
                ))
                .size(12)
                .horizontal_alignment(iced::alignment::Horizontal::Center)
            )
            .width(Length::Fill)
            .center_x(),
        ]
                .spacing(8)
                .align_items(Alignment::Center)
        )
            .style(theme::Container::Box)
            .padding(15)
            .into()
    }

    fn vulnerability_detail<'a>(&'a self, vuln: &'a Vulnerability) -> Element<'a, Message> {
        container(
            column![
            // Header section
            container(
                row![
                    Text::new(&vuln.cve_id).size(28),
                    Space::with_width(Length::Fill),
                    button(Text::new("×").size(28))
                        .on_press(Message::ClearSelection)
                        .style(theme::Button::Destructive)
                        .padding(8),
                ]
                .align_items(Alignment::Center)
            ).padding(16),

            Rule::horizontal(10),

            // Severity and date section
            container(
                column![
                    row![
                        Text::new("Severity: ").size(16),
                        Text::new(&vuln.severity)
                            .size(16)
                            .style(theme::Text::Color(format_severity(&vuln.severity))),
                    ].spacing(8),
                    Space::with_height(Length::Fixed(8.0)),
                    Text::new(format!("Published: {}", format_date(vuln.published_date)))
                        .size(14),
                ]
            )
            .style(theme::Container::Box)
            .padding(16),

            Space::with_height(Length::Fixed(16.0)),

            // Description section
            container(
                column![
                    Text::new("Description").size(20),
                    Space::with_height(Length::Fixed(8.0)),
                    Text::new(vuln.description.as_deref().unwrap_or("No description available"))
                        .size(16),
                ]
            )
            .style(theme::Container::Box)
            .padding(16),

            Space::with_height(Length::Fixed(16.0)),

            // Impact section
            container(
                column![
                    Text::new("Impact").size(20),
                    Space::with_height(Length::Fixed(8.0)),
                    Text::new(vuln.impact.as_deref().unwrap_or("No impact information available"))
                        .size(16),
                ]
            )
            .style(theme::Container::Box)
            .padding(16),

            Space::with_height(Length::Fixed(16.0)),

            // Mitigation section
            container(
                column![
                    Text::new("Mitigation").size(20),
                    Space::with_height(Length::Fixed(8.0)),
                    Text::new(vuln.mitigation.as_deref().unwrap_or("No mitigation steps available"))
                        .size(16),
                ]
            )
            .style(theme::Container::Box)
            .padding(16),
        ]
                .spacing(0)
        )
            .padding(20)
            .style(theme::Container::Box)
            .into()
    }

    fn control_panel(&self) -> Element<Message> {
        container(
            row![
                container(
                    pick_list(
                        vec![
                            super::types::SortField::None,
                            super::types::SortField::CVE,
                            super::types::SortField::Severity,
                            super::types::SortField::Date
                        ],
                        Some(self.sort_field.clone()),
                        Message::SortFieldSelected
                    )
                    .width(Length::Fixed(150.0))
                    .padding(8)
                )
                .style(theme::Container::Box),

                button(
                    Text::new(if self.sort_ascending { "↑" } else { "↓" }).size(20)
                )
                .on_press(Message::ToggleSortOrder)
                .padding(8),

                container(
                    pick_list(
                        vec![
                            super::types::FilterSeverity::All,
                            super::types::FilterSeverity::High,
                            super::types::FilterSeverity::Medium,
                            super::types::FilterSeverity::Low
                        ],
                        Some(self.filter_severity.clone()),
                        Message::FilterSeverityChanged
                    )
                    .width(Length::Fixed(150.0))
                    .padding(8)
                )
                .style(theme::Container::Box),

                Space::with_width(Length::Fill),

                Checkbox::new("Show Statistics", self.show_statistics)
                    .on_toggle(Message::ToggleStatistics)
                    .spacing(8),
            ]
                .spacing(12)
                .align_items(Alignment::Center)
        )
            .style(theme::Container::Box)
            .padding(15)
            .into()
    }
}