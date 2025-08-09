use bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

#[allow(non_snake_case)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quote {
    #[serde(rename = "_id")]
    pub id : Option<ObjectId>,
    pub fullName : String,
    pub phone : String,
    pub email : Option<String>,
    pub country : String,
    pub wilaya : String,
    pub address : Option<String>,
    pub spaceType : String,
    pub spaceTypeOther : Option<String>,
    pub projectState: String,
    pub area: f64,
    pub floorsNumber: u32,
    pub vacantLand: bool,
    pub serviceType: String,
    pub serviceTypeOther: Option<String>,
    pub haveFiles: bool,
    pub files: Option<Vec<String>>,
    pub startDate: String,
    pub note: Option<String>,
    pub firstTime: Option<bool>,
    pub hearAboutUs: Option<String>,

    pub status: Option<String>,

    pub createdAt: Option<String>,
    pub updatedAt: Option<String>,
}

#[allow(non_snake_case)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteNote {
    #[serde(rename = "_id")]
    pub id: Option<ObjectId>,
    pub quoteId: ObjectId,
    pub title: String,
    pub content: String,
    pub createdAt: String,
    pub updatedAt: String,
}