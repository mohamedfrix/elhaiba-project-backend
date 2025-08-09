use axum::{extract::{State, Path, Query}, response::IntoResponse, Json, http::StatusCode};
use crate::model::quote::QuoteNote;
use crate::dto::quote_dto::QuoteResponseDto;
use bson::oid::ObjectId;
use axum::{extract::Multipart};
use crate::service::quote_service::{QuoteServiceImpl, QuoteService};
use crate::model::quote::Quote;
use crate::dto::quote_dto::{QuoteDto, File, UpdateQuoteStatusRequest, AddQuoteNoteRequest};
use crate::util::error::HandlerError;
use std::sync::Arc;
use bytes::BytesMut;

use validator::Validate;

#[allow(dead_code)]

pub async fn create_quote_handler(
    State(service): State<Arc<QuoteServiceImpl>>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, HandlerError> {
    use tracing::{info, error, debug};
    info!("[create_quote_handler] Handler called");
    let mut json_data: Option<Quote> = None;
    let mut file_objs: Vec<File> = Vec::new();
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    let mut _file_count: usize = 0;

    while let Some(field) = match multipart.next_field().await {
        Ok(f) => f,
        Err(e) => {
            error!("[create_quote_handler] Error getting next field: {}", e);
            return Err(HandlerError {
                error: crate::util::error::HandlerErrorKind::BadRequest,
                message: format!("Failed to get next field: {}", e),
                details: None,
            });
        }
    } {
        let name = field.name().map(|s| s.to_string()).unwrap_or_default();
        debug!("[create_quote_handler] Processing field: {}", name);
        if name == "json" {
            let data = match field.bytes().await {
                Ok(d) => d,
                Err(e) => {
                    error!("[create_quote_handler] Failed to read json field: {}", e);
                    return Err(HandlerError {
                        error: crate::util::error::HandlerErrorKind::BadRequest,
                        message: format!("Failed to read json field: {}", e),
                        details: None,
                    });
                }
            };
            let quote: Quote = match serde_json::from_slice(&data) {
                Ok(q) => q,
                Err(e) => {
                    error!("[create_quote_handler] Invalid JSON: {}", e);
                    return Err(HandlerError {
                        error: crate::util::error::HandlerErrorKind::BadRequest,
                        message: format!("Invalid JSON: {}", e),
                        details: None,
                    });
                }
            };
            info!("[create_quote_handler] Parsed JSON successfully");
            json_data = Some(quote);
        } else if name.starts_with("file") {
            let filename = field.file_name().map(|s| s.to_string()).unwrap_or_default();
            let content_type = field.content_type().map(|s| s.to_string()).unwrap_or_default();
            let mut buf = BytesMut::new();
            let mut stream = field;
            while let Some(chunk) = match stream.chunk().await {
                Ok(c) => c,
                Err(e) => {
                    error!("[create_quote_handler] Error reading file chunk: {}", e);
                    return Err(HandlerError {
                        error: crate::util::error::HandlerErrorKind::BadRequest,
                        message: format!("Failed to read file chunk: {}", e),
                        details: None,
                    });
                }
            } {
                buf.extend_from_slice(&chunk);
            }
            info!("[create_quote_handler] Received file: {} ({} bytes)", filename, buf.len());
            let file_obj = File {
                filename: filename.clone(),
                content_type,
                content: buf.to_vec(),
                size: buf.len(),
            };
            file_objs.push(file_obj);
            files.push((filename, buf.to_vec()));
        } else if name == "fileCount" {
            let data = match field.bytes().await {
                Ok(d) => d,
                Err(e) => {
                    error!("[create_quote_handler] Failed to read fileCount: {}", e);
                    return Err(HandlerError {
                        error: crate::util::error::HandlerErrorKind::BadRequest,
                        message: format!("Failed to read fileCount: {}", e),
                        details: None,
                    });
                }
            };
            let count_str = String::from_utf8_lossy(&data);
            _file_count = count_str.trim().parse().unwrap_or(0);
            info!("[create_quote_handler] fileCount: {}", _file_count);
        }
    }

    let quote = match json_data {
        Some(q) => q,
        None => {
            error!("[create_quote_handler] Missing quote JSON data");
            return Err(HandlerError {
                error: crate::util::error::HandlerErrorKind::BadRequest,
                message: "Missing quote JSON data".to_string(),
                details: None,
            });
        }
    };

    // Build QuoteDto from quote and files
    let quote_dto = QuoteDto {
        full_name: quote.fullName,
        phone: quote.phone,
        email: quote.email,
        country: quote.country,
        wilaya: quote.wilaya,
        address: quote.address,
        space_type: quote.spaceType,
        space_type_other: quote.spaceTypeOther,
        project_state: quote.projectState,
        area: quote.area,
        floors_number: quote.floorsNumber,
        vacant_land: quote.vacantLand,
        service_type: quote.serviceType,
        service_type_other: quote.serviceTypeOther,
        have_files: !file_objs.is_empty(),
        files: if !file_objs.is_empty() { Some(file_objs) } else { None },
        start_date: quote.startDate,
        note: quote.note,
        first_time: quote.firstTime,
        hear_about_us: quote.hearAboutUs,
    };

    let created = QuoteService::register_quote(&*service, quote_dto).await.map_err(|e| HandlerError {
        error: crate::util::error::HandlerErrorKind::Internal,
        message: format!("Failed to create quote: {}", e),
        details: None,
    })?;

    Ok(Json(created))
}


// Handler: List Quotes (admin only)
pub async fn list_quotes_handler(
    State(service): State<Arc<QuoteServiceImpl>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<impl IntoResponse, HandlerError> {
    let page = params.get("page").and_then(|v| v.parse().ok()).unwrap_or(1);
    let limit = params.get("limit").and_then(|v| v.parse().ok()).unwrap_or(20);
    let quotes = service.list_quotes(page, limit).await.map_err(|e| HandlerError {
        error: crate::util::error::HandlerErrorKind::Internal,
        message: format!("Failed to list quotes: {}", e),
        details: None,
    })?;
    Ok(Json(quotes))
}

// Handler: Update Quote Status (admin only)
pub async fn update_quote_status_handler(
    State(service): State<Arc<QuoteServiceImpl>>,
    Path((id,)): Path<(String,)>,
    Json(payload): Json<UpdateQuoteStatusRequest>,
) -> Result<impl IntoResponse, HandlerError> {
    let id = ObjectId::parse_str(&id).map_err(|_| HandlerError {
        error: crate::util::error::HandlerErrorKind::BadRequest,
        message: "Invalid quote id".to_string(),
        details: None,
    })?;
    if let Err(e) = payload.validate() {
        return Err(HandlerError {
            error: crate::util::error::HandlerErrorKind::BadRequest,
            message: format!("Validation error: {}", e),
            details: None,
        });
    }
    let updated = service.update_quote_status(id, &payload.status).await.map_err(|e| HandlerError {
        error: crate::util::error::HandlerErrorKind::Internal,
        message: format!("Failed to update status: {}", e),
        details: None,
    })?;
    Ok(Json(updated))
}

// Handler: Get Quote (admin only)
pub async fn get_quote_handler(
    State(service): State<Arc<QuoteServiceImpl>>,
    Path((id,)): Path<(String,)>,
) -> Result<impl IntoResponse, HandlerError> {
    let id = ObjectId::parse_str(&id).map_err(|_| HandlerError {
        error: crate::util::error::HandlerErrorKind::BadRequest,
        message: "Invalid quote id".to_string(),
        details: None,
    })?;
    let quote = service.get_quote(id).await.map_err(|e| HandlerError {
        error: crate::util::error::HandlerErrorKind::Internal,
        message: format!("Failed to get quote: {}", e),
        details: None,
    })?;
    Ok(Json(quote))
}

// Handler: Add Quote Note (admin only)
pub async fn add_quote_note_handler(
    State(service): State<Arc<QuoteServiceImpl>>,
    Json(payload): Json<AddQuoteNoteRequest>,
) -> Result<impl IntoResponse, HandlerError> {
    if let Err(e) = payload.validate() {
        return Err(HandlerError {
            error: crate::util::error::HandlerErrorKind::BadRequest,
            message: format!("Validation error: {}", e),
            details: None,
        });
    }
    // Convert AddQuoteNoteRequest to QuoteNote
    let note = QuoteNote {
        id: None,
        quoteId: match ObjectId::parse_str(&payload.quote_id) {
            Ok(id) => id,
            Err(_) => {
                return Err(HandlerError {
                    error: crate::util::error::HandlerErrorKind::BadRequest,
                    message: "Invalid quote_id".to_string(),
                    details: None,
                });
            }
        },
        title: String::new(), // or set from payload if needed
        content: payload.content.clone(),
        createdAt: chrono::Utc::now().to_rfc3339(),
        updatedAt: chrono::Utc::now().to_rfc3339(),
    };
    let created = service.add_note(note).await.map_err(|e| HandlerError {
        error: crate::util::error::HandlerErrorKind::Internal,
        message: format!("Failed to add note: {}", e),
        details: None,
    })?;
    Ok(Json(created))
}

// Handler: Get Quote Note (admin only)
pub async fn get_quote_note_handler(
    State(service): State<Arc<QuoteServiceImpl>>,
    Path((id,)): Path<(String,)>,
) -> Result<impl IntoResponse, HandlerError> {
    let id = ObjectId::parse_str(&id).map_err(|_| HandlerError {
        error: crate::util::error::HandlerErrorKind::BadRequest,
        message: "Invalid note id".to_string(),
        details: None,
    })?;
    let note = service.get_note(id).await.map_err(|e| HandlerError {
        error: crate::util::error::HandlerErrorKind::Internal,
        message: format!("Failed to get note: {}", e),
        details: None,
    })?;
    Ok(Json(note))
}

// Handler: List Quote Notes (admin only)
pub async fn list_quote_notes_handler(
    State(service): State<Arc<QuoteServiceImpl>>,
    Path((quote_id,)): Path<(String,)>,
) -> Result<impl IntoResponse, HandlerError> {
    let quote_id = ObjectId::parse_str(&quote_id).map_err(|_| HandlerError {
        error: crate::util::error::HandlerErrorKind::BadRequest,
        message: "Invalid quote id".to_string(),
        details: None,
    })?;
    let notes = service.list_notes_for_quote(quote_id).await.map_err(|e| HandlerError {
        error: crate::util::error::HandlerErrorKind::Internal,
        message: format!("Failed to list notes: {}", e),
        details: None,
    })?;
    Ok(Json(notes))
}