use crate::model::quote::Quote;
use crate::repository::repository_error::{
    RepositoryError, RepositoryResult,
};
use crate::config::mongo_conf::MongoConfig;
use async_trait::async_trait;
use bson::{doc, oid::ObjectId};
use tracing::{info, error};
use futures::stream::StreamExt; // For try_next on MongoDB cursor

#[async_trait]
pub trait QuoteRepository : Send + Sync {
    async fn create (&self, quote: Quote) -> RepositoryResult<Quote>;
    async fn get_by_id(&self, id: ObjectId) -> RepositoryResult<Quote>;
    async fn update(&self, id: ObjectId, quote: Quote) -> RepositoryResult<Quote>;
    async fn update_status(&self, id: ObjectId, status: &str) -> RepositoryResult<Quote>;
    async fn delete(&self, id: ObjectId) -> RepositoryResult<()>;
    async fn list(&self, page: u32, limit: u32) -> RepositoryResult<Vec<Quote>>;
    async fn count(&self) -> RepositoryResult<u64>;
}

pub struct MongoQuoteRepository {
    collection: mongodb::Collection<Quote>,
}

impl MongoQuoteRepository {
    /// Create a new MongoQuoteRepository using MongoConfig
    pub async fn new(config: &MongoConfig) -> Result<Self, mongodb::error::Error> {
        use mongodb::{options::{ClientOptions, Credential, ResolverConfig}, Client};

        // Parse client options from URI
        let mut client_options = ClientOptions::parse_with_resolver_config(&config.uri, ResolverConfig::cloudflare()).await?;
        client_options.app_name = Some("ElhaibaBackend".to_string());
        client_options.max_pool_size = Some(config.pool_size);
        client_options.connect_timeout = Some(std::time::Duration::from_secs(config.connection_timeout_secs));

        // Set credentials if username and password are provided
        if let (Some(ref username), Some(ref password)) = (&config.username, &config.password) {
            client_options.credential = Some(Credential::builder()
                .username(username.clone())
                .password(password.clone())
                .build());
        }

        let client = Client::with_options(client_options)?;
        let db = client.database(&config.database);
        let collection_name = config.quote_collection.as_deref().unwrap_or("quotes");
        let collection = db.collection::<Quote>(collection_name);
        Ok(MongoQuoteRepository { collection })
    }
}

#[async_trait]
impl QuoteRepository for MongoQuoteRepository {

    #[tracing::instrument(skip(self), fields(quote = ?quote))]
    async fn create(&self, quote: Quote) -> RepositoryResult<Quote> {
        info!(
            quote = ?quote,
            "Creating new quote"
        );
        let mut new_quote = quote.clone();
        // Set id manually before inserting
        new_quote.id = Some(ObjectId::new());
        new_quote.status = Some("New".to_string());
        let time = chrono::Local::now();
        new_quote.createdAt = Some(time.to_rfc3339());
        new_quote.updatedAt = Some(time.to_rfc3339());

        let result = self.collection.insert_one(new_quote.clone(), None).await;
        match result {
            Ok(_) => {
                info!("Quote created successfully");
                Ok(new_quote)
            },
            Err(e) => {
                error!("Failed to create quote: {}", e);
                Err(RepositoryError::database(format!("Failed to create quote: {}", e)))    
            }
        }
    }

    #[tracing::instrument(skip(self), fields(id = %id))]
    async fn get_by_id(&self, id: ObjectId) -> RepositoryResult<Quote> {
        info!("Fetching quote by ID: {}", id);
        let filter = doc! { "_id": id };
        let result = self.collection.find_one(filter, None).await;
        match result {
            Ok(Some(quote)) => {
                info!("Quote found: {:?}", quote);
                Ok(quote)
            },
            Ok(None) => {
                error!("Quote not found for ID: {}", id);
                Err(RepositoryError::not_found(format!("Quote not found for ID: {}", id)))
            },
            Err(e) => {
                error!("Failed to fetch quote by ID: {}", e);
                Err(RepositoryError::database(format!("Failed to fetch quote by ID: {}", e)))
            }
        }
    }

    #[tracing::instrument(skip(self), fields(id = %id, quote = ?quote))]
    async fn update(&self, id: ObjectId, quote: Quote) -> RepositoryResult<Quote> {
        info!("Updating quote with ID: {}", id);
        let filter = doc! { "_id": id };
        // Convert to document and remove _id
        let mut doc = bson::to_document(&quote).map_err(|e| RepositoryError::serialization(format!("Failed to serialize quote: {}", e)))?;
        doc.remove("_id");
        let update = doc! { "$set": doc };
        let result = self.collection.update_one(filter, update, None).await;
        match result {
            Ok(update_result) if update_result.modified_count > 0 => {
                info!("Quote updated successfully for ID: {}", id);
                Ok(quote)
            },
            Ok(_) => {
                error!("No quote found to update for ID: {}", id);
                Err(RepositoryError::not_found(format!("No quote found to update for ID: {}", id)))
            },
            Err(e) => {
                error!("Failed to update quote: {}", e);
                Err(RepositoryError::database(format!("Failed to update quote: {}", e)))
            }
        }
    }

    #[tracing::instrument(skip(self), fields(id = %id, status = %status))]
    async fn update_status(&self, id: ObjectId, status: &str) -> RepositoryResult<Quote> {
        info!(quote_id= %id, status = %status, "Updating quote status");
        let filter = doc! { "_id": id };
        let update = doc! { "$set": { "status": status, "updatedAt": chrono::Local::now().to_rfc3339() } };
        let result = self.collection.update_one(filter, update, None).await;
        match result {
            Ok(update_result) if update_result.modified_count > 0 => {
                info!("Quote status updated successfully for ID: {}", id);
                let mut updated_quote = self.get_by_id(id).await?;
                updated_quote.status = Some(status.to_string());
                Ok(updated_quote)
            },
            Ok(_) => {
                error!("No quote found to update status for ID: {}", id);
                Err(RepositoryError::not_found(format!("No quote found to update status for ID: {}", id)))
            },
            Err(e) => {
                error!("Failed to update quote status: {}", e);
                Err(RepositoryError::database(format!("Failed to update quote status: {}", e)))
            }
        }
    }

    #[tracing::instrument(skip(self), fields(id = %id))]
    async fn delete(&self, id: ObjectId) -> RepositoryResult<()> {
        info!("Deleting quote with ID: {}", id);
        let filter = doc! { "_id": id };
        let result = self.collection.delete_one(filter, None).await;
        match result {
            Ok(delete_result) if delete_result.deleted_count > 0 => {
                info!("Quote deleted successfully for ID: {}", id);
                Ok(())
            },
            Ok(_) => {
                error!("No quote found to delete for ID: {}", id);
                Err(RepositoryError::not_found(format!("No quote found to delete for ID: {}", id)))
            },
            Err(e) => {
                error!("Failed to delete quote: {}", e);
                Err(RepositoryError::database(format!("Failed to delete quote: {}", e)))
            }
        }
    }

    #[tracing::instrument(skip(self), fields(page = page, limit = limit))]
    async fn list(&self, page: u32, limit: u32) -> RepositoryResult<Vec<Quote>> {
        info!("Listing quotes with page: {}, limit: {}", page, limit);
        let skip = (page - 1) * limit;
        let cursor = self.collection.find(None, None).await;
        match cursor {
            Ok(mut cursor) => {
                let mut quotes = Vec::new();
                while let Some(quote) = cursor.next().await {
                    match quote {
                        Ok(q) => quotes.push(q),
                        Err(e) => {
                            error!("Failed to deserialize quote: {}", e);
                            return Err(RepositoryError::serialization(format!("Failed to deserialize quote: {}", e)));
                        }
                    }
                }
                info!("Fetched {} quotes", quotes.len());
                Ok(quotes.into_iter().skip(skip as usize).take(limit as usize).collect())
            },
            Err(e) => {
                error!("Failed to list quotes: {}", e);
                Err(RepositoryError::database(format!("Failed to list quotes: {}", e)))
            }
        }
    }

    #[tracing::instrument(skip(self))]
    async fn count(&self) -> RepositoryResult<u64> {
        info!("Counting total number of quotes");
        let count = self.collection.count_documents(None, None).await;
        match count {
            Ok(count) => {
                info!("Total quotes count: {}", count);
                Ok(count)
            },
            Err(e) => {
                error!("Failed to count quotes: {}", e);
                Err(RepositoryError::database(format!("Failed to count quotes: {}", e)))
            }
        }
    }
}
