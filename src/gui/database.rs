use crate::db::connection::SqlitePool;
use crate::models::vulnerability::Vulnerability;
use crate::repositories::vulnerability_repo::VulnerabilityRepository;
use super::types::{SortField, FilterSeverity};
use std::sync::Arc;
use log::{error, info};

pub async fn load_vulnerabilities(
    pool: Arc<SqlitePool>,
    search_query: String,
    page: usize,
    page_size: usize,
    sort_field: SortField,
    sort_ascending: bool,
    filter_severity: FilterSeverity,
) -> Result<(Vec<Vulnerability>, usize), String> {
    let repo = VulnerabilityRepository::new(pool);

    match repo.search_vulnerabilities(&search_query, page, page_size).await {
        Ok((mut vulnerabilities, total_pages)) => {
            // Apply additional filtering
            if !matches!(filter_severity, FilterSeverity::All) {
                let severity = match filter_severity {
                    FilterSeverity::High => "high",
                    FilterSeverity::Medium => "medium",
                    FilterSeverity::Low => "low",
                    FilterSeverity::All => unreachable!(),
                };
                vulnerabilities.retain(|v| v.severity.to_lowercase() == severity);
            }

            // Apply sorting
            match sort_field {
                SortField::CVE => {
                    vulnerabilities.sort_by(|a, b| {
                        if sort_ascending {
                            a.cve_id.cmp(&b.cve_id)
                        } else {
                            b.cve_id.cmp(&a.cve_id)
                        }
                    });
                },
                SortField::Severity => {
                    vulnerabilities.sort_by(|a, b| {
                        if sort_ascending {
                            a.severity.cmp(&b.severity)
                        } else {
                            b.severity.cmp(&a.severity)
                        }
                    });
                },
                SortField::Date => {
                    vulnerabilities.sort_by(|a, b| {
                        if sort_ascending {
                            a.published_date.cmp(&b.published_date)
                        } else {
                            b.published_date.cmp(&a.published_date)
                        }
                    });
                },
                SortField::None => (),
            }

            Ok((vulnerabilities, total_pages))
        },
        Err(e) => {
            error!("Error loading vulnerabilities: {}", e);
            Err(format!("Failed to load vulnerabilities: {}", e))
        }
    }
}