// src/main.rs

mod db;
mod models;
mod repositories;
mod gui;
mod utils;

use anyhow::{Context, Result};
use db::connection::{self, SqlitePool};
use db::schema;
use gui::app;
use log::{error, info, warn};
use repositories::vulnerability_repo;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tokio::time::{sleep, Duration};
use utils::csv_importer::import_vulnerabilities_from_csv;
use utils::nvd_api::NvdApiClient;

const BATCH_SIZE: usize = 50;
const UPDATE_INTERVAL: Duration = Duration::from_secs(3600); // 1 hour

struct App {
	pool: Arc<SqlitePool>,
	nvd_client: NvdApiClient,
	shutdown_signal: tokio::sync::broadcast::Sender<()>,
}

impl App {
	async fn new() -> Result<Self> {
		utils::logger::init();
		info!("Starting Vulnerability Management Database application");

		let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
		let pool = Arc::new(
			connection::establish_pool()
				.context("Failed to establish database connection pool")?,
		);

		let nvd_client = NvdApiClient::new(pool.clone())
			.context("Failed to create NVD API client")?;

		info!("Database connection pool and NVD client established");

		Ok(App {
			pool,
			nvd_client,
			shutdown_signal: shutdown_tx,
		})
	}

	async fn init_database(&self) -> Result<()> {
		let conn = self.pool.get().context("Failed to get database connection")?;
		schema::create_tables(&conn).context("Failed to create database tables")?;
		info!("Database tables initialized successfully");
		Ok(())
	}

	async fn import_initial_data(&self) -> Result<()> {
		let vulnerabilities = vulnerability_repo::get_all_vulnerabilities(self.pool.clone())
			.await
			.context("Failed to check existing vulnerabilities")?;

		if vulnerabilities.is_empty() {
			info!("Database is empty, starting initial data import");
			let csv_path = self.get_csv_path()?;

			match import_vulnerabilities_from_csv(csv_path.to_string_lossy().into_owned(), self.pool.clone()).await {
				Ok(count) => {
					info!("Successfully imported {} vulnerabilities from CSV", count);

					// After CSV import, update with NVD data
					info!("Starting initial NVD data enrichment");
					match self.update_vulnerability_data(true).await {
						Ok(updated) => info!("Enriched {} vulnerabilities with NVD data", updated),
						Err(e) => warn!("Some NVD updates failed: {}", e),
					}
				}
				Err(e) => {
					error!("Failed to import vulnerabilities from CSV: {}", e);
				}
			}
		} else {
			info!("Database contains {} vulnerabilities", vulnerabilities.len());
		}
		Ok(())
	}

	async fn update_vulnerability_data(&self, initial: bool) -> Result<usize> {
		let batch_size = if initial { BATCH_SIZE * 2 } else { BATCH_SIZE };
		self.nvd_client.batch_update_vulnerabilities(batch_size).await
	}

	fn get_csv_path(&self) -> Result<PathBuf> {
		let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
		path.push("src");
		path.push("db");
		path.push("allitems1.csv");

		if !path.exists() {
			return Err(anyhow::anyhow!("CSV file not found at {:?}", path));
		}
		Ok(path)
	}

	async fn start_update_scheduler(&self) -> Result<()> {
		let nvd_client = self.nvd_client.clone();
		let mut shutdown_rx = self.shutdown_signal.subscribe();

		tokio::spawn(async move {
			loop {
				tokio::select! {
				_ = sleep(UPDATE_INTERVAL) => {
					match nvd_client.batch_update_vulnerabilities(BATCH_SIZE).await {
						Ok(count) => info!("Scheduled update completed: {} vulnerabilities updated", count),
						Err(e) => error!("Scheduled update failed: {}", e),
					}
				}
				_ = shutdown_rx.recv() => {
					info!("Update scheduler received shutdown signal");
					break;
				}
			}
			}
		});

		Ok(())
	}

	async fn run(&self) -> Result<()> {
		self.init_database().await?;
		self.import_initial_data().await?;
		self.start_update_scheduler().await?;

		let mut shutdown_rx = self.shutdown_signal.subscribe();

		let shutdown_signal = self.shutdown_signal.clone();
		tokio::spawn(async move {
			match signal::ctrl_c().await {
				Ok(()) => {
					info!("Received Ctrl+C signal");
					let _ = shutdown_signal.send(());
				}
				Err(err) => {
					error!("Failed to listen for ctrl-c signal: {}", err);
				}
			}
		});

		tokio::select! {
			result = app::run(self.pool.clone()) => {
				if let Err(e) = result {
					error!("GUI application error: {}", e);
					return Err(e.into());
				}
			}
			_ = shutdown_rx.recv() => {
				info!("Received shutdown signal, closing application");
			}
		}

		self.cleanup().await;
		Ok(())
	}

	async fn cleanup(&self) {
		info!("Cleaning up resources and stopping background tasks...");
		let _ = self.shutdown_signal.send(());
		sleep(Duration::from_secs(1)).await; // Give tasks time to clean up
		info!("Cleanup completed");
	}
}

#[tokio::main]
async fn main() -> Result<()> {
	let app = App::new().await?;
	app.run().await
}