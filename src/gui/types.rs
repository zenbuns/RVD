use crate::models::vulnerability::Vulnerability;
use anyhow::Result;

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

#[derive(Debug, Clone)]
pub enum OperationType {
    Loading,
    Searching,
    Filtering,
    Exporting,
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
    LoadingProgress(f32),
    OperationTypeChanged(OperationType),
    ClearSearch,
    ExportData,
}