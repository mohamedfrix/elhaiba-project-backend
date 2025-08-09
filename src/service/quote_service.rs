use tracing::{info, error, instrument};
use crate::model::quote::{Quote, QuoteNote};
use crate::model::quote_file::QuoteFile;
use crate::repository::quote_repo::{QuoteRepository, MongoQuoteRepository};
use crate::repository::quote_note_repo::{QuoteNoteRepository, MongoQuoteNoteRepository};
use crate::repository::quote_file_repo::{QuoteFileRepository, MongoQuoteFileRepository};
use crate::util::minio::MinioService;
use crate::util::error::ServiceError;
use crate::config::minio_conf::MinioConfig;
use crate::dto::quote_dto::QuoteDto;
use crate::config::mongo_conf::MongoConfig;
use bson::oid::ObjectId;

use crate::dto::quote_dto::QuoteResponseDto;

use async_trait::async_trait;

#[async_trait]
pub trait QuoteService: Send + Sync {
	// Quote CRUD
	async fn register_quote(&self, quote_dto: QuoteDto) -> Result<Quote, ServiceError>;
	async fn get_quote(&self, id: ObjectId) -> Result<QuoteResponseDto, ServiceError>;
	async fn update_quote(&self, id: ObjectId, quote: Quote) -> Result<Quote, ServiceError>;
	async fn delete_quote(&self, id: ObjectId) -> Result<(), ServiceError>;
	async fn list_quotes(&self, page: u32, limit: u32) -> Result<Vec<Quote>, ServiceError>;
	async fn update_quote_status(&self, id: ObjectId, status: &str) -> Result<Quote, ServiceError>;

	// Quote Note CRUD
	async fn add_note(&self, note: QuoteNote) -> Result<QuoteNote, ServiceError>;
	async fn get_note(&self, id: ObjectId) -> Result<QuoteNote, ServiceError>;
	async fn update_note(&self, id: ObjectId, note: QuoteNote) -> Result<QuoteNote, ServiceError>;
	async fn delete_note(&self, id: ObjectId) -> Result<(), ServiceError>;
	async fn list_notes_for_quote(&self, quote_id: ObjectId) -> Result<Vec<QuoteNote>, ServiceError>;
}

pub struct QuoteServiceImpl {
	pub quote_repo: MongoQuoteRepository,
	pub note_repo: MongoQuoteNoteRepository,
	pub quote_file_repo: std::sync::Arc<MongoQuoteFileRepository>,
	pub minio_service: std::sync::Arc<MinioService>,
}

impl QuoteServiceImpl {
	pub async fn new(
		mongo_config: &MongoConfig,
		minio_config: &MinioConfig,
	) -> Result<Self, Box<dyn std::error::Error>> {
		let quote_repo = MongoQuoteRepository::new(mongo_config).await?;
		let note_repo = MongoQuoteNoteRepository::new(mongo_config).await?;
	let quote_file_repo = std::sync::Arc::new(MongoQuoteFileRepository::new(mongo_config).await?);
		let minio_service = std::sync::Arc::new(MinioService::new(minio_config.clone()).await?);
		Ok(QuoteServiceImpl {
			quote_repo,
			note_repo,
			quote_file_repo,
			minio_service,
		})
	}
}


#[async_trait]
impl QuoteService for QuoteServiceImpl {
	// Quote CRUD
	async fn register_quote(&self, quote_dto: QuoteDto) -> Result<Quote, ServiceError> {
		use chrono::Utc;
		info!("Registering new quote with files");

		// 1. Create Quote (without files)
	let quote = Quote {
			id: None,
			fullName: quote_dto.full_name.clone(),
			phone: quote_dto.phone.clone(),
			email: quote_dto.email.clone(),
			country: quote_dto.country.clone(),
			wilaya: quote_dto.wilaya.clone(),
			address: quote_dto.address.clone(),
			spaceType: quote_dto.space_type.clone(),
			spaceTypeOther: quote_dto.space_type_other.clone(),
			projectState: quote_dto.project_state.clone(),
			area: quote_dto.area,
			floorsNumber: quote_dto.floors_number,
			vacantLand: quote_dto.vacant_land,
			serviceType: quote_dto.service_type.clone(),
			serviceTypeOther: quote_dto.service_type_other.clone(),
			haveFiles: quote_dto.have_files,
			files: None, // will be filled after upload
			startDate: quote_dto.start_date.clone(),
			note: quote_dto.note.clone(),
			firstTime: quote_dto.first_time,
			hearAboutUs: quote_dto.hear_about_us.clone(),
			status: Some("pending".to_string()),
			createdAt: Some(Utc::now().to_rfc3339()),
			updatedAt: Some(Utc::now().to_rfc3339()),
		};

		// Insert quote to get its ObjectId
		let mut inserted_quote = self.quote_repo.create(quote.clone()).await.map_err(ServiceError::from)?;
		let quote_id = inserted_quote.id.clone().ok_or(ServiceError::InternalError("Failed to get inserted quote id".to_string()))?;

		// 2. Handle file uploads if present
		let mut file_paths = Vec::new();
		if let Some(files) = &quote_dto.files {
			for file in files {
				let uuid = uuid::Uuid::new_v4().to_string();
				let extension = file.filename.rsplit('.').next().filter(|s| *s != &file.filename).map(|ext| format!(".{}", ext)).unwrap_or_default();
				let object_name = format!("quotes/{}/{}{}", quote_id, uuid, extension);
				// Upload to MinIO with unique name
				self.minio_service.put_object(&object_name, file.content.clone(), Some(&file.content_type)).await.map_err(|e| ServiceError::InternalError(format!("MinIO upload error: {e}")))?;
				// Create QuoteFile metadata (original filename preserved)
				let quote_file = QuoteFile {
					id: Some(bson::oid::ObjectId::new()),
					quote_id: quote_id.clone(),
					file_path: object_name.clone(),
					original_filename: file.filename.clone(),
					content_type: file.content_type.clone(),
					size: file.size,
					created_at: Some(Utc::now().to_rfc3339()),
				};
				self.quote_file_repo.create(quote_file).await.map_err(ServiceError::from)?;
				file_paths.push(object_name);
			}
		}

		// 3. Update quote with file paths
		if !file_paths.is_empty() {
			inserted_quote.files = Some(file_paths);
			self.quote_repo.update(quote_id.clone(), inserted_quote.clone()).await.map_err(ServiceError::from)?;
		}

		info!("Quote registered successfully with files");
		Ok(inserted_quote)
	}

	// #[instrument(skip(self), fields(id = %id))]
	// async fn get_quote(&self, id: ObjectId) -> Result<Quote, ServiceError> {
	// 	info!("Getting quote by id");
	// 	let res = self.quote_repo.get_by_id(id).await;
	// 	match res {
	// 		Ok(q) => {
	// 			info!("Quote fetched successfully");
	// 			Ok(q)
	// 		},
	// 		Err(e) => {
	// 			error!("Failed to fetch quote: {e}");
	// 			Err(ServiceError::from(e))
	// 		}
	// 	}
	// }

	#[instrument(skip(self), fields(id = %id))]
	async fn get_quote(&self, id: ObjectId) -> Result<QuoteResponseDto, ServiceError> {
		info!("Getting quote by id");
		let res = self.quote_repo.get_by_id(id).await;
		let quote = match &res {
			Ok(q) => {
				info!("Quote fetched successfully");
				q.clone()
			},
			Err(e) => {
				error!("Failed to fetch quote: {e}");
				return Err(ServiceError::NotFound(format!("Quote not found: {}", id)));
			}
		};


		let minio_conf = self.minio_service.config.clone();

		// For each file path, generate a download link (if files exist)
		let mut file_links: Option<Vec<String>> = None;
		if let Some(files) = &quote.files {
			let mut links = Vec::new();
			for file_path in files {
				links.push(self.minio_service.generate_download_link(&minio_conf.links_prefix, &minio_conf.bucket_name.clone(), file_path));
			}
			file_links = Some(links);
		}

		Ok(QuoteResponseDto {
			quote,
			files: file_links,
		})
	}

	#[instrument(skip(self, quote), fields(id = %id, quote = ?quote))]
	async fn update_quote(&self, id: ObjectId, quote: Quote) -> Result<Quote, ServiceError> {
		info!("Updating quote");
		let res = self.quote_repo.update(id, quote).await;
		match &res {
			Ok(_) => info!("Quote updated successfully"),
			Err(e) => error!("Failed to update quote: {e}"),
		}
		res.map_err(ServiceError::from)
	}

	#[instrument(skip(self), fields(id = %id))]
	async fn delete_quote(&self, id: ObjectId) -> Result<(), ServiceError> {
		info!("Deleting quote");
		let res = self.quote_repo.delete(id).await;
		match &res {
			Ok(_) => info!("Quote deleted successfully"),
			Err(e) => error!("Failed to delete quote: {e}"),
		}
		res.map_err(ServiceError::from)
	}

	#[instrument(skip(self), fields(page, limit))]
	async fn list_quotes(&self, page: u32, limit: u32) -> Result<Vec<Quote>, ServiceError> {
		info!("Listing quotes");
		let res = self.quote_repo.list(page, limit).await;
		match &res {
			Ok(quotes) => info!("Fetched {} quotes", quotes.len()),
			Err(e) => error!("Failed to list quotes: {e}"),
		}
		res.map_err(ServiceError::from)
	}

	#[instrument(skip(self), fields(id = %id, status))]
	async fn update_quote_status(&self, id: ObjectId, status: &str) -> Result<Quote, ServiceError> {
		info!("Updating quote status");
		let res = self.quote_repo.update_status(id, status).await;
		match &res {
			Ok(_) => info!("Quote status updated successfully"),
			Err(e) => error!("Failed to update quote status: {e}"),
		}
		res.map_err(ServiceError::from)
	}

	// Quote Note CRUD
	#[instrument(skip(self, note), fields(note = ?note))]
	async fn add_note(&self, note: QuoteNote) -> Result<QuoteNote, ServiceError> {
		info!("Adding note to quote");
		let res = self.note_repo.create(note).await;
		match &res {
			Ok(_) => info!("Note added successfully"),
			Err(e) => error!("Failed to add note: {e}"),
		}
		res.map_err(ServiceError::from)
	}

	#[instrument(skip(self), fields(id = %id))]
	async fn get_note(&self, id: ObjectId) -> Result<QuoteNote, ServiceError> {
		info!("Getting note by id");
		let res = self.note_repo.get_by_id(id).await;
		match &res {
			Ok(_) => info!("Note fetched successfully"),
			Err(e) => error!("Failed to fetch note: {e}"),
		}
		res.map_err(ServiceError::from)
	}

	#[instrument(skip(self, note), fields(id = %id, note = ?note))]
	async fn update_note(&self, id: ObjectId, note: QuoteNote) -> Result<QuoteNote, ServiceError> {
		info!("Updating note");
		let res = self.note_repo.update(id, note).await;
		match &res {
			Ok(_) => info!("Note updated successfully"),
			Err(e) => error!("Failed to update note: {e}"),
		}
		res.map_err(ServiceError::from)
	}

	#[instrument(skip(self), fields(id = %id))]
	async fn delete_note(&self, id: ObjectId) -> Result<(), ServiceError> {
		info!("Deleting note");
		let res = self.note_repo.delete(id).await;
		match &res {
			Ok(_) => info!("Note deleted successfully"),
			Err(e) => error!("Failed to delete note: {e}"),
		}
		res.map_err(ServiceError::from)
	}

	#[instrument(skip(self), fields(quote_id = %quote_id))]
	async fn list_notes_for_quote(&self, quote_id: ObjectId) -> Result<Vec<QuoteNote>, ServiceError> {
		info!("Listing notes for quote");
		let res = self.note_repo.list_by_quote(quote_id).await;
		match &res {
			Ok(notes) => info!("Fetched {} notes", notes.len()),
			Err(e) => error!("Failed to list notes: {e}"),
		}
		res.map_err(ServiceError::from)
	}
}

