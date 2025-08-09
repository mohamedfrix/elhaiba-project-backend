use crate::model::quote::QuoteNote;
use crate::repository::repository_error::{RepositoryError, RepositoryResult};
use crate::config::mongo_conf::MongoConfig;
use async_trait::async_trait;
use bson::{doc, oid::ObjectId};
use tracing::{info, error};
use futures::stream::StreamExt;

#[async_trait]
pub trait QuoteNoteRepository: Send + Sync {
    async fn create(&self, note: QuoteNote) -> RepositoryResult<QuoteNote>;
    async fn get_by_id(&self, id: ObjectId) -> RepositoryResult<QuoteNote>;
    async fn update(&self, id: ObjectId, note: QuoteNote) -> RepositoryResult<QuoteNote>;
    async fn delete(&self, id: ObjectId) -> RepositoryResult<()>;
    async fn list_by_quote(&self, quote_id: ObjectId) -> RepositoryResult<Vec<QuoteNote>>;
}

pub struct MongoQuoteNoteRepository {
    collection: mongodb::Collection<QuoteNote>,
}

impl MongoQuoteNoteRepository {
    pub async fn new(config: &MongoConfig) -> Result<Self, mongodb::error::Error> {
        use mongodb::{options::{ClientOptions, Credential, ResolverConfig}, Client};
        let mut client_options = ClientOptions::parse_with_resolver_config(&config.uri, ResolverConfig::cloudflare()).await?;
        client_options.app_name = Some("ElhaibaBackend".to_string());
        client_options.max_pool_size = Some(config.pool_size);
        client_options.connect_timeout = Some(std::time::Duration::from_secs(config.connection_timeout_secs));
        if let (Some(ref username), Some(ref password)) = (&config.username, &config.password) {
            client_options.credential = Some(Credential::builder()
                .username(username.clone())
                .password(password.clone())
                .build());
        }
        let client = Client::with_options(client_options)?;
        let db = client.database(&config.database);
        let collection = db.collection::<QuoteNote>("quote_notes");
        Ok(MongoQuoteNoteRepository { collection })
    }
}

#[async_trait]
impl QuoteNoteRepository for MongoQuoteNoteRepository {
    async fn create(&self, mut note: QuoteNote) -> RepositoryResult<QuoteNote> {
        info!(note = ?note, "Creating new quote note");
        note.id = Some(ObjectId::new());
        let result = self.collection.insert_one(note.clone(), None).await;
        match result {
            Ok(_) => {
                info!("Quote note created successfully");
                Ok(note)
            },
            Err(e) => {
                error!("Failed to create quote note: {}", e);
                Err(RepositoryError::database(format!("Failed to create quote note: {}", e)))
            }
        }
    }

    async fn get_by_id(&self, id: ObjectId) -> RepositoryResult<QuoteNote> {
        info!("Fetching quote note by ID: {}", id);
        let filter = doc! { "_id": id };
        let result = self.collection.find_one(filter, None).await;
        match result {
            Ok(Some(note)) => Ok(note),
            Ok(None) => Err(RepositoryError::not_found(format!("Quote note not found for ID: {}", id))),
            Err(e) => Err(RepositoryError::database(format!("Failed to fetch quote note by ID: {}", e))),
        }
    }

    async fn update(&self, id: ObjectId, note: QuoteNote) -> RepositoryResult<QuoteNote> {
        info!("Updating quote note with ID: {}", id);
        let filter = doc! { "_id": id };
        // Convert to document and remove _id
        let mut doc = bson::to_document(&note).map_err(|e| RepositoryError::serialization(format!("Failed to serialize quote note: {}", e)))?;
        doc.remove("_id");
        let update = doc! { "$set": doc };
        let result = self.collection.update_one(filter, update, None).await;
        match result {
            Ok(update_result) if update_result.modified_count > 0 => Ok(note),
            Ok(_) => Err(RepositoryError::not_found(format!("No quote note found to update for ID: {}", id))),
            Err(e) => Err(RepositoryError::database(format!("Failed to update quote note: {}", e))),
        }
    }

    async fn delete(&self, id: ObjectId) -> RepositoryResult<()> {
        info!("Deleting quote note with ID: {}", id);
        let filter = doc! { "_id": id };
        let result = self.collection.delete_one(filter, None).await;
        match result {
            Ok(delete_result) if delete_result.deleted_count > 0 => Ok(()),
            Ok(_) => Err(RepositoryError::not_found(format!("No quote note found to delete for ID: {}", id))),
            Err(e) => Err(RepositoryError::database(format!("Failed to delete quote note: {}", e))),
        }
    }

    async fn list_by_quote(&self, quote_id: ObjectId) -> RepositoryResult<Vec<QuoteNote>> {
        info!("Listing notes for quote ID: {}", quote_id);
        let filter = doc! { "quoteId": quote_id };
        let mut cursor = self.collection.find(filter, None).await.map_err(|e| RepositoryError::database(format!("Failed to list quote notes: {}", e)))?;
        let mut notes = Vec::new();
        while let Some(note) = cursor.next().await {
            match note {
                Ok(n) => notes.push(n),
                Err(e) => return Err(RepositoryError::serialization(format!("Failed to deserialize quote note: {}", e))),
            }
        }
        Ok(notes)
    }
}
