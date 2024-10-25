use crate::models::vulnerability::Vulnerability;
use crate::models::robot::Robot;
use anyhow::Result;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Tab {
    Vulnerabilities,
    RobotInventory,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SortField {
    CVE,
    Severity,
    Date,
    None,
    // Add robot-specific sort fields
    RobotName,
    Manufacturer,
}

impl std::fmt::Display for SortField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SortField::CVE => write!(f, "CVE ID"),
            SortField::Severity => write!(f, "Severity"),
            SortField::Date => write!(f, "Date"),
            SortField::None => write!(f, "No Sort"),
            SortField::RobotName => write!(f, "Robot Name"),
            SortField::Manufacturer => write!(f, "Manufacturer"),
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
    AddingRobot,
    UpdatingRobot,
    DeletingRobot,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RobotFilterType {
    All,
    ByManufacturer,
    ByVulnerability,
    BySoftware,
}

impl std::fmt::Display for RobotFilterType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RobotFilterType::All => write!(f, "All Robots"),
            RobotFilterType::ByManufacturer => write!(f, "By Manufacturer"),
            RobotFilterType::ByVulnerability => write!(f, "By Vulnerability"),
            RobotFilterType::BySoftware => write!(f, "By Software"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RobotForm {
    pub name: String,
    pub manufacturer: String,
    pub specifications: String,
    pub software_versions: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum Message {
    // Existing vulnerability messages
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

    // New robot-related messages
    TabSelected(Tab),
    RobotsLoaded(Result<Vec<Robot>, String>),
    RobotSelected(usize),
    RobotFilterChanged(String),
    RobotFilterTypeChanged(RobotFilterType),
    AddRobotClicked,
    EditRobotClicked(i32),
    DeleteRobotClicked(i32),

    // Robot form messages
    RobotFormNameChanged(String),
    RobotFormManufacturerChanged(String),
    RobotFormSpecificationsChanged(String),
    RobotFormSoftwareAdded(String),
    RobotFormSoftwareRemoved(usize),
    RobotFormSubmitted,
    RobotFormCancelled,

    // Robot operation results
    RobotAdded(Result<Robot, String>),
    RobotUpdated(Result<Robot, String>),
    RobotDeleted(Result<(), String>),

    // Software and vulnerability correlation
    LoadRobotVulnerabilities(i32),
    RobotVulnerabilitiesLoaded(Result<Vec<Vulnerability>, String>),
    LoadRobotSoftware(i32),
    RobotSoftwareLoaded(Result<Vec<String>, String>),

    // Batch operations
    ExportRobotData,
    ImportRobotData(String),
    BatchUpdateRobots,

    // Error handling
    ShowError(String),
    ClearError,
}

// Helper function to convert operation type to string for logging/display
pub fn operation_type_to_string(op: &OperationType) -> &'static str {
    match op {
        OperationType::Loading => "Loading data",
        OperationType::Searching => "Searching records",
        OperationType::Filtering => "Filtering results",
        OperationType::Exporting => "Exporting data",
        OperationType::AddingRobot => "Adding new robot",
        OperationType::UpdatingRobot => "Updating robot",
        OperationType::DeletingRobot => "Deleting robot",
    }
}

// Helper function to create a default robot form
pub fn default_robot_form() -> RobotForm {
    RobotForm {
        name: String::new(),
        manufacturer: String::new(),
        specifications: String::new(),
        software_versions: Vec::new(),
    }
}

// Helper function to validate robot form
pub fn validate_robot_form(form: &RobotForm) -> Result<(), String> {
    if form.name.trim().is_empty() {
        return Err("Robot name is required".to_string());
    }
    if form.manufacturer.trim().is_empty() {
        return Err("Manufacturer is required".to_string());
    }
    Ok(())
}