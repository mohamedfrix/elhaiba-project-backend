use crate::model::user::User;
use crate::repository::repository_error::{RepositoryResult, RepositoryError};
use crate::config::mongo_conf::MongoConfig;
use async_trait::async_trait;
use bson::oid::ObjectId;

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn insert(&self, user: User) -> RepositoryResult<User>;
    async fn update(&self, id: ObjectId, user: User) -> RepositoryResult<User>;
    async fn find_by_email(&self, email: &str) -> RepositoryResult<Option<User>>;
    async fn find_by_id(&self, id: &ObjectId) -> RepositoryResult<Option<User>>;
}

pub struct UserRepositoryImpl {
    collection: mongodb::Collection<User>,
}

impl UserRepositoryImpl {
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
        let collection = db.collection::<User>("users");
        Ok(UserRepositoryImpl { collection })
    }
}

#[async_trait]
impl UserRepository for UserRepositoryImpl {
    async fn insert(&self, mut user: User) -> RepositoryResult<User> {
        use chrono::Local;
        use bson::oid::ObjectId;
        user.id = Some(ObjectId::new());
        let now = Local::now().to_rfc3339();
        user.created_at = Some(now.clone());
        user.updated_at = Some(now);
        let result = self.collection.insert_one(user.clone(), None).await;
        match result {
            Ok(_) => Ok(user),
            Err(e) => Err(RepositoryError::database(format!("Failed to insert user: {}", e))),
        }
    }

    async fn update(&self, id: ObjectId, user: User) -> RepositoryResult<User> {
        use bson::doc;
        let filter = doc! { "_id": id };
        let mut doc = bson::to_document(&user).map_err(|e| RepositoryError::serialization(format!("Failed to serialize user: {}", e)))?;
        doc.remove("_id");
        let update = doc! { "$set": doc };
        let result = self.collection.update_one(filter, update, None).await;
        match result {
            Ok(update_result) if update_result.modified_count > 0 => Ok(user),
            Ok(_) => Err(RepositoryError::not_found(format!("No user found to update for ID: {}", id))),
            Err(e) => Err(RepositoryError::database(format!("Failed to update user: {}", e))),
        }
    }
    async fn find_by_email(&self, email: &str) -> RepositoryResult<Option<User>> {
        let filter = bson::doc! { "email": email };
        let user = self.collection.find_one(filter, None).await.map_err(|e| RepositoryError::database(format!("Failed to find user by email: {}", e)))?;
        Ok(user)
    }

    async fn find_by_id(&self, id: &ObjectId) -> RepositoryResult<Option<User>> {
        let filter = bson::doc! { "_id": id };
        let user = self.collection.find_one(filter, None).await.map_err(|e| RepositoryError::database(format!("Failed to find user by id: {}", e)))?;
        Ok(user)
    }
}
