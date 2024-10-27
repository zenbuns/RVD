use super::constants::DISPLAY_PAGE_SIZE;
use super::formatters::{format_date, format_severity};
use super::state::AppState;
use super::types::Message;
use crate::models::vulnerability::Vulnerability;
use iced::{
	alignment::{Horizontal, Vertical},
	theme,
	widget::{
		button, column, container, pick_list, row, scrollable, text_input, Checkbox, Column, Row,
		Rule, Space, Text,
	},
	Alignment, Color, Element, Length,
};

pub trait ViewRenderer {
	fn search_bar(&self) -> Element<Message>;
	fn statistics(&self) -> Element<Message>;
	fn vulnerability_list(&self) -> Element<Message>;
	fn vulnerability_card<'a>(
		&self,
		vuln: &'a Vulnerability,
		idx: usize,
	) -> Element<'a, Message>;
	fn pagination_controls(&self) -> Element<Message>;
	fn vulnerability_detail<'a>(
		&'a self,
		vuln: &'a Vulnerability,
	) -> Element<'a, Message>;
	fn control_panel(&self) -> Element<Message>;
}

impl ViewRenderer for AppState {
	fn search_bar(&self) -> Element<Message> {
		container(
			row![
				text_input(
					"Search by CVE ID, description, or severity...",
					&self.search_query
				)
				.on_input(Message::SearchQueryChanged)
				.on_submit(Message::SearchSubmitted)
				.padding(12)
				.size(16)
				.width(Length::Fill),
				button(
					Text::new("Search")
						.size(16)
						.horizontal_alignment(Horizontal::Center),
				)
				.style(theme::Button::Primary)
				.on_press(Message::SearchSubmitted)
				.padding(12),
				button(
					Text::new("Refresh")
						.size(16)
						.horizontal_alignment(Horizontal::Center),
				)
				.on_press(Message::RefreshData)
				.padding(12),
			]
				.spacing(10)
				.align_items(Alignment::Center),
		)
			.style(theme::Container::Box)
			.padding(10)
			.into()
	}

	fn statistics(&self) -> Element<Message> {
		let total = self.vulnerabilities.len();
		let high = self
			.vulnerabilities
			.iter()
			.filter(|v| v.severity.eq_ignore_ascii_case("high"))
			.count();
		let medium = self
			.vulnerabilities
			.iter()
			.filter(|v| v.severity.eq_ignore_ascii_case("medium"))
			.count();
		let low = self
			.vulnerabilities
			.iter()
			.filter(|v| v.severity.eq_ignore_ascii_case("low"))
			.count();

		container(
			column![
				Text::new("Vulnerability Overview")
					.size(28)
					.horizontal_alignment(Horizontal::Center),
				Space::with_height(Length::Fixed(10.0)),
				Rule::horizontal(1),
				Space::with_height(Length::Fixed(10.0)),
				Text::new(format!("Total Vulnerabilities: {}", total))
					.size(18)
					.horizontal_alignment(Horizontal::Center),
				Space::with_height(Length::Fixed(10.0)),
				row![
					container(
						column![
							Text::new("High Severity")
								.style(theme::Text::Color(format_severity("high")))
								.size(16),
							Text::new(format!("{} ({}%)", high, (high * 100) / total.max(1)))
								.size(24)
								.horizontal_alignment(Horizontal::Center),
						]
						.spacing(4),
					)
					.style(theme::Container::Box)
					.padding(10)
					.width(Length::Fill),
					container(
						column![
							Text::new("Medium Severity")
								.style(theme::Text::Color(format_severity("medium")))
								.size(16),
							Text::new(format!("{} ({}%)", medium, (medium * 100) / total.max(1)))
								.size(24)
								.horizontal_alignment(Horizontal::Center),
						]
						.spacing(4),
					)
					.style(theme::Container::Box)
					.padding(10)
					.width(Length::Fill),
					container(
						column![
							Text::new("Low Severity")
								.style(theme::Text::Color(format_severity("low")))
								.size(16),
							Text::new(format!("{} ({}%)", low, (low * 100) / total.max(1)))
								.size(24)
								.horizontal_alignment(Horizontal::Center),
						]
						.spacing(4),
					)
					.style(theme::Container::Box)
					.padding(10)
					.width(Length::Fill),
				]
				.spacing(10),
			]
				.spacing(10),
		)
			.padding(15)
			.style(theme::Container::Box)
			.into()
	}

	fn vulnerability_list(&self) -> Element<Message> {
		let content = if self.loading && self.displayed_vulnerabilities.is_empty() {
			column![
				Space::with_height(Length::Fixed(20.0)),
				Text::new("Loading vulnerabilities...")
					.size(20)
					.horizontal_alignment(Horizontal::Center),
			]
		} else if self.displayed_vulnerabilities.is_empty() {
			column![
				Space::with_height(Length::Fixed(20.0)),
				Text::new("No vulnerabilities found")
					.size(20)
					.horizontal_alignment(Horizontal::Center),
			]
		} else {
			Column::with_children(
				self.displayed_vulnerabilities
					.iter()
					.enumerate()
					.map(|(idx, vuln)| self.vulnerability_card(vuln, idx))
					.collect::<Vec<Element<'_, Message>>>(),
			)
				.spacing(8)
		};

		scrollable(
			container(content)
				.width(Length::Fill)
				.padding(10),
		)
			.on_scroll(|viewport| Message::ScrollChanged(viewport.relative_offset().y))
			.height(Length::Fill)
			.into()
	}

	fn vulnerability_card<'a>(
		&self,
		vuln: &'a Vulnerability,
		idx: usize,
	) -> Element<'a, Message> {
		let is_selected = self.selected_vulnerability == Some(idx);

		button(
			container(
				column![
					row![
						Text::new(&vuln.cve_id)
							.size(18)
							.width(Length::FillPortion(2)),
						Text::new(&vuln.severity)
							.size(14)
							.style(theme::Text::Color(format_severity(&vuln.severity)))
							.width(Length::Shrink)
							.horizontal_alignment(Horizontal::Right),
					]
					.spacing(10)
					.align_items(Alignment::Center),
					Text::new(format_date(vuln.published_date))
						.size(12)
						.style(theme::Text::Color(Color::from_rgb8(100, 100, 100))),
					Space::with_height(Length::Fixed(5.0)),
					Text::new(
						vuln.description
							.as_deref()
							.unwrap_or("No description available"),
					)
					.size(14)
					.width(Length::Fill),
				]
					.spacing(5)
					.padding(10),
			)
				.width(Length::Fill)
				.style(if is_selected {
					theme::Container::Box
				} else {
					theme::Container::Transparent
				}),
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
		container(
			row![
				button("First")
					.style(if self.current_page > 0 {
						theme::Button::Primary
					} else {
						theme::Button::Secondary
					})
					.on_press(Message::PageChanged(0))
					.padding(8),
				button("Prev")
					.style(if self.current_page > 0 {
						theme::Button::Primary
					} else {
						theme::Button::Secondary
					})
					.on_press(Message::PageChanged(self.current_page.saturating_sub(1)))
					.padding(8),
				Text::new(format!(
					"Page {} of {}",
					self.current_page + 1,
					self.total_pages
				))
				.size(14),
				button("Next")
					.style(if self.current_page + 1 < self.total_pages {
						theme::Button::Primary
					} else {
						theme::Button::Secondary
					})
					.on_press(Message::PageChanged(self.current_page + 1))
					.padding(8),
				button("Last")
					.style(if self.current_page + 1 < self.total_pages {
						theme::Button::Primary
					} else {
						theme::Button::Secondary
					})
					.on_press(Message::PageChanged(
						self.total_pages.saturating_sub(1),
					))
					.padding(8),
			]
				.spacing(10)
				.align_items(Alignment::Center),
		)
			.padding(10)
			.style(theme::Container::Box)
			.into()
	}

	fn vulnerability_detail<'a>(
		&'a self,
		vuln: &'a Vulnerability,
	) -> Element<'a, Message> {
		container(
			scrollable(
				column![
				// Header
				row![
					Text::new(&vuln.cve_id)
						.size(28)
						.width(Length::Fill),
					button(Text::new("Close").size(16))
						.on_press(Message::ClearSelection)
						.style(theme::Button::Destructive)
						.padding(5),
				]
				.align_items(Alignment::Center)
				.padding(10),
				Rule::horizontal(1),
				// Severity and date
				row![
					Text::new("Severity:")
						.size(16),
					Text::new(&vuln.severity)
						.size(16)
						.style(theme::Text::Color(format_severity(&vuln.severity))),
					Space::with_width(Length::Fixed(20.0)),
					Text::new(format!("Published: {}", format_date(vuln.published_date)))
						.size(14),
				]
				.spacing(10)
				.padding(10),
				Rule::horizontal(1),
				// Description
				column![
					Text::new("Description").size(20),
					Text::new(
						vuln.description
							.as_deref()
							.unwrap_or("No description available"),
					)
					.size(16)
					.width(Length::Fill),
				]
				.spacing(5)
				.padding(10),
				// Impact
				column![
					Text::new("Impact").size(20),
					Text::new(
						vuln.impact
							.as_deref()
							.unwrap_or("No impact information available"),
					)
					.size(16)
					.width(Length::Fill),
				]
				.spacing(5)
				.padding(10),
				// Mitigation
				column![
					Text::new("Mitigation").size(20),
					Text::new(
						vuln.mitigation
							.as_deref()
							.unwrap_or("No mitigation steps available"),
					)
					.size(16)
					.width(Length::Fill),
				]
				.spacing(5)
				.padding(10),
			]
					.spacing(10),
			),
		)
			.padding(10)
			.style(theme::Container::Box)
			.into()
	}


	fn control_panel(&self) -> Element<Message> {
		container(
			row![
				pick_list(
					[
						super::types::SortField::None,
						super::types::SortField::CVE,
						super::types::SortField::Severity,
						super::types::SortField::Date,
					],
					Some(self.sort_field.clone()),
					Message::SortFieldSelected,
				)
				.width(Length::Fixed(150.0))
				.padding(5),
				button(
					Text::new(if self.sort_ascending { "↑" } else { "↓" }).size(16),
				)
				.on_press(Message::ToggleSortOrder)
				.padding(5),
				pick_list(
					[
						super::types::FilterSeverity::All,
						super::types::FilterSeverity::High,
						super::types::FilterSeverity::Medium,
						super::types::FilterSeverity::Low,
					],
					Some(self.filter_severity.clone()),
					Message::FilterSeverityChanged,
				)
				.width(Length::Fixed(150.0))
				.padding(5),
				Space::with_width(Length::Fill),
				Checkbox::new("Show Statistics", self.show_statistics)
					.on_toggle(Message::ToggleStatistics)
					.spacing(5),
			]
				.spacing(10)
				.align_items(Alignment::Center),
		)
			.style(theme::Container::Box)
			.padding(10)
			.into()
	}
}
