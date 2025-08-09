use bson::oid::ObjectId;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteFile {
    #[serde(rename = "_id")]
    pub id: Option<ObjectId>,
    pub quote_id: ObjectId,
    pub file_path: String,
    pub original_filename: String,
    pub content_type: String,
    pub size: usize,
    pub created_at: Option<String>,
}
