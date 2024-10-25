// src/models/robot.rs

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Robot {
    pub robot_id: Option<i32>,
    pub name: String,
    pub specifications: Option<String>,
    pub manufacturer: Option<String>,
}
