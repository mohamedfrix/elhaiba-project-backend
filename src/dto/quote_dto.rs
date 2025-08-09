// use bytes::Bytes;
use crate::model::quote::Quote;
use serde::{Deserialize, Serialize};

use validator::Validate;

#[derive(Debug, Clone)]
pub struct File {
    pub filename: String,
    pub content_type: String,
    pub content: Vec<u8>,
    pub size: usize,
}

#[derive(Debug, Clone)]
pub struct QuoteDto {
    pub full_name: String,
    pub phone: String,
    pub email: Option<String>,
    pub country: String,
    pub wilaya: String,
    pub address: Option<String>,
    pub space_type: String,
    pub space_type_other: Option<String>,
    pub project_state: String,
    pub area: f64,
    pub floors_number: u32,
    pub vacant_land: bool,
    pub service_type: String,
    pub service_type_other: Option<String>,
    pub have_files: bool,
    pub files: Option<Vec<File>>,
    pub start_date: String,
    pub note: Option<String>,
    pub first_time: Option<bool>,
    pub hear_about_us: Option<String>,
}

// --- Validated DTOs for request validation ---

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct CreateQuoteRequest {
    #[validate(length(min = 2, max = 100))]
    pub full_name: String,

    #[validate(length(min = 6, max = 20))]
    pub phone: String,

    #[validate(email)]
    pub email: Option<String>,

    #[validate(length(min = 2, max = 100))]
    pub country: String,

    #[validate(length(min = 2, max = 100))]
    pub wilaya: String,

    pub address: Option<String>,

    #[validate(length(min = 2, max = 100))]
    pub space_type: String,

    pub space_type_other: Option<String>,

    #[validate(length(min = 2, max = 100))]
    pub project_state: String,

    #[validate(range(min = 1.0))]
    pub area: f64,

    #[validate(range(min = 1, max = 100))]
    pub floors_number: u32,

    pub vacant_land: bool,

    #[validate(length(min = 2, max = 100))]
    pub service_type: String,

    pub service_type_other: Option<String>,

    pub have_files: bool,

    pub start_date: String,

    pub note: Option<String>,

    pub first_time: Option<bool>,

    pub hear_about_us: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct UpdateQuoteStatusRequest {
    #[validate(length(min = 2, max = 50))]
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AddQuoteNoteRequest {
    #[validate(length(min = 2, max = 1000))]
    pub content: String,

    #[validate(length(equal = 24))] // MongoDB ObjectId hex string
    pub quote_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteResponseDto {
    pub quote : Quote,
    pub files: Option<Vec<String>>,
}