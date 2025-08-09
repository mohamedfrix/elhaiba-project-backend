
use axum::{Router, routing::get};
use std::net::SocketAddr;
use tracing::info;
use crate::config::app_conf::AppConfig;
use crate::config::admin_user_conf::AdminUserConfig;
use crate::service::user_service::{UserServiceImpl, UserService};
use crate::model::user::User;
use std::sync::Arc;

// Import your routers here
// use crate::router::quote_router::create_quote_router;
// use crate::router::user_router::create_user_router;


pub struct App {
    config: AppConfig,
    router: Router,
    pub user_service: Arc<UserServiceImpl>,
    pub quote_service: Arc<crate::service::quote_service::QuoteServiceImpl>,
}

impl App {
    pub async fn new() -> Self {
        let config = AppConfig::from_env();

        use crate::repository::user_repo::UserRepositoryImpl;
        use crate::util::jwt::JwtTokenUtilsImpl;
        use crate::util::password_reset::RedisPasswordResetService;
        use crate::config::PasswordResetConfig;
        use crate::util::redis::RedisService;
        use crate::config::jwt_conf::JwtConfig;
        use crate::config::mongo_conf::MongoConfig;
        use crate::config::redis_conf::RedisConfig;
        use crate::repository::quote_repo::MongoQuoteRepository;
        use crate::repository::quote_note_repo::MongoQuoteNoteRepository;
        use crate::service::quote_service::QuoteServiceImpl;

        let jwt_config = JwtConfig::from_env().expect("JWT config error");
        let mongo_config = MongoConfig::from_env().expect("Mongo config error");
        let redis_config = RedisConfig::from_env().expect("Redis config error");
        let password_reset_config = PasswordResetConfig::from_env().expect("PasswordResetConfig error");
        let redis_service = Box::new(RedisService::new(redis_config.clone()).await.expect("RedisService error")) as Box<dyn crate::util::redis::RedisServiceTrait>;
        let password_reset = Arc::new(
            RedisPasswordResetService::new(password_reset_config, redis_service)
                .expect("Failed to create RedisPasswordResetService")
        ) as Arc<dyn crate::util::password_reset::PasswordResetService + Send + Sync>;
        let user_repo = Arc::new(UserRepositoryImpl::new(&mongo_config).await.expect("User repo error"));
        let jwt_utils = Arc::new(JwtTokenUtilsImpl::new(jwt_config));
        let user_service = Arc::new(UserServiceImpl::new(user_repo, jwt_utils.clone(), password_reset));

        use crate::repository::quote_file_repo::MongoQuoteFileRepository;
        use crate::util::minio::MinioService;
        use crate::config::minio_conf::MinioConfig;
        let minio_config = MinioConfig::from_env().expect("Minio config error");
        let quote_repo = MongoQuoteRepository::new(&mongo_config).await.expect("Quote repo error");
        let note_repo = MongoQuoteNoteRepository::new(&mongo_config).await.expect("Quote note repo error");
        let quote_file_repo = Arc::new(MongoQuoteFileRepository::new(&mongo_config).await.expect("Quote file repo error"));
        let minio_service = Arc::new(MinioService::new(minio_config).await.expect("Minio service error"));
        let quote_service = Arc::new(QuoteServiceImpl {
            quote_repo,
            note_repo,
            quote_file_repo,
            minio_service,
        });

        // --- AdminAuthState setup ---
        use crate::middlewares::admin_middleware::AdminAuthState;
        let admin_auth_state = Arc::new(AdminAuthState {
            jwt_utils: jwt_utils.clone(),
            user_service: user_service.clone(),
        });

        let mut app = App { config, router: Router::new(), user_service, quote_service };
        app.router = app.create_router_with_admin(admin_auth_state);
        app.create_first_admin_user().await;
        app
    }


    fn create_router_with_admin(&self, admin_auth_state: Arc<crate::middlewares::admin_middleware::AdminAuthState>) -> Router {
        use crate::router::quote_router::quote_router;
        use crate::router::user_router::user_router;
        Router::new()
            .merge(quote_router(self.quote_service.clone(), admin_auth_state.clone()))
            .merge(user_router(self.user_service.clone(), admin_auth_state))
            .route("/health", get(|| async { "OK" }))
    }

    pub async fn start(self) {
        let addr = SocketAddr::new(self.config.host.parse().expect("Invalid host"), self.config.port);
        info!("🚀 Server running at http://{}", addr);
        let listener = tokio::net::TcpListener::bind(addr).await.expect("Failed to bind address");
        axum::serve(listener, self.router).await.expect("Failed to start server");
    }
    async fn create_first_admin_user(&self) {
        use tracing::{info, warn, error};
        // Load admin config
        let admin_conf = match AdminUserConfig::from_env() {
            Ok(c) => c,
            Err(e) => {
                warn!("Admin user config not loaded: {e}");
                return;
            }
        };

        // Check if admin user already exists by email
        use crate::repository::user_repo::UserRepository;
        let user_repo = self.user_service.user_repo.clone();
        match user_repo.find_by_email(&admin_conf.email).await {
            Ok(Some(_)) => {
                info!("Admin user already exists, skipping creation.");
                return;
            },
            Ok(None) => { /* continue to create */ },
            Err(e) => {
                error!("Failed to check for existing admin user: {e}");
                return;
            }
        }

        let user = User {
            id: None,
            username: admin_conf.username.clone(),
            first_name: admin_conf.first_name.clone(),
            last_name: admin_conf.last_name.clone(),
            email: admin_conf.email.clone(),
            password_hash: String::new(), // Will be set by register
            role: "admin".to_string(),
            created_at: None,
            updated_at: None,
        };
        match self.user_service.register(user, admin_conf.password.clone()).await {
            Ok(_) => info!("First admin user created."),
            Err(e) => error!("Failed to create admin user: {e}"),
        }
    }
}
