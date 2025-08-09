use crate::model::quote_file::QuoteFile;
use crate::repository::repository_error::RepositoryError;
use crate::config::mongo_conf::MongoConfig;
use bson::oid::ObjectId;
use async_trait::async_trait;
use futures::stream::StreamExt;

#[async_trait]
pub trait QuoteFileRepository: Send + Sync {
    async fn create(&self, file: QuoteFile) -> Result<QuoteFile, RepositoryError>;
    async fn find_by_quote_id(&self, quote_id: &ObjectId) -> Result<Vec<QuoteFile>, RepositoryError>;
    async fn delete_by_id(&self, id: &ObjectId) -> Result<(), RepositoryError>;
}

pub struct MongoQuoteFileRepository {
    collection: mongodb::Collection<QuoteFile>,
}

impl MongoQuoteFileRepository {
    /// Create a new MongoQuoteFileRepository using MongoConfig
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
        let collection = db.collection::<QuoteFile>("quote_files");
        Ok(MongoQuoteFileRepository { collection })
    }
}

#[async_trait]
impl QuoteFileRepository for MongoQuoteFileRepository {
    async fn create(&self, file: QuoteFile) -> Result<QuoteFile, RepositoryError> {
        self.collection.insert_one(&file, None).await.map_err(RepositoryError::from)?;
        Ok(file)
    }

    async fn find_by_quote_id(&self, quote_id: &ObjectId) -> Result<Vec<QuoteFile>, RepositoryError> {
        let filter = mongodb::bson::doc! { "quote_id": quote_id };
        let mut cursor = self.collection.find(filter, None).await.map_err(RepositoryError::from)?;
        let mut files = Vec::new();
        while let Some(result) = cursor.next().await {
            let file = result.map_err(RepositoryError::from)?;
            files.push(file);
        }
        Ok(files)
    }

    async fn delete_by_id(&self, id: &ObjectId) -> Result<(), RepositoryError> {
        self.collection.delete_one(mongodb::bson::doc! {"_id": id}, None).await.map_err(RepositoryError::from)?;
        Ok(())
    }
}
