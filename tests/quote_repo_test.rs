use elhaiba_backend::model::quote::Quote;
use elhaiba_backend::repository::quote_repo::{MongoQuoteRepository, QuoteRepository};
use elhaiba_backend::repository::repository_error::{RepositoryResult, RepositoryError};
use tokio;
use tracing::{info, error, debug};
use elhaiba_backend::config::mongo_conf::MongoConfig;

async fn setup_quote_repository() -> RepositoryResult<MongoQuoteRepository> {
    // Load environment variables from .env file
    let _ = dotenv::dotenv();
    let config = MongoConfig::from_env().map_err(|e| RepositoryError::database(format!("Failed to load MongoConfig: {}", e)))?;
    MongoQuoteRepository::new(&config).await.map_err(|e| RepositoryError::database(format!("Failed to setup MongoQuoteRepository: {}", e)))
}

#[tokio::test]
async fn test_quote_repository_workflow() {
    let quote_repo = setup_quote_repository().await.expect("Failed to setup quote repository");

    // Create a Quote with all optional fields and real data
    let mut quote = Quote {
        id: None, // Will be set by the repository
        fullName: "Mohamed Frihaoui".to_string(),
        phone: "+213770000000".to_string(),
        email: Some("mohamed.frihaoui@ensia.edu.dz".to_string()),
        country: "Algeria".to_string(),
        wilaya: "Algiers".to_string(),
        address: Some("123 Main St, Hydra".to_string()),
        spaceType: "Residential".to_string(),
        spaceTypeOther: Some("Villa".to_string()),
        projectState: "Planning".to_string(),
        area: 250.0,
        floorsNumber: 2,
        vacantLand: true,
        serviceType: "Architecture".to_string(),
        serviceTypeOther: Some("Interior Design".to_string()),
        haveFiles: true,
        files: Some(vec!["plan.pdf".to_string(), "photo.jpg".to_string()]),
        startDate: "2025-08-01".to_string(),
        note: Some("Urgent project".to_string()),
        firstTime: Some(true),
        hearAboutUs: Some("Google Search".to_string()),
        status: None,
        createdAt: None,
        updatedAt: None,
    };

    // Insert the quote
    let inserted_quote = quote_repo.create(quote.clone()).await.expect("Failed to insert quote");
    assert!(inserted_quote.id.is_some());
    let quote_id = inserted_quote.id.clone().unwrap();

    // change quote status
    let updated_quote = quote_repo.update_status(quote_id, "Replied").await.expect("Failed to update quote status");
    assert_eq!(updated_quote.status, Some("Replied".to_string()));

    // Get by id
    let fetched_quote = quote_repo.get_by_id(quote_id).await.expect("Failed to get quote by id");
    assert_eq!(fetched_quote.fullName, quote.fullName);
    assert_eq!(fetched_quote.email, quote.email);

    // Insert multiple quotes
    let mut quotes = vec![];
    for i in 0..3 {
        let mut q = quote.clone();
        q.fullName = format!("Test User {}", i);
        q.email = Some(format!("user{}@test.com", i));
        let inserted = quote_repo.create(q).await.expect("Failed to insert quote");
        quotes.push(inserted);
    }
    assert_eq!(quotes.len(), 3);

    // Delete one quote
    let delete_id = quotes[0].id.clone().unwrap();
    quote_repo.delete(delete_id).await.expect("Failed to delete quote");

    // List quotes (page 1, limit 10)
    let listed_quotes = quote_repo.list(1, 10).await.expect("Failed to list quotes");
    assert!(listed_quotes.len() >= 3); // At least the ones we inserted

    // Update a quote
    let mut to_update = quotes[1].clone();
    to_update.note = Some("Updated note".to_string());
    let updated_quote = quote_repo.update(to_update.id.clone().unwrap(), to_update.clone()).await.expect("Failed to update quote");
    assert_eq!(updated_quote.note, Some("Updated note".to_string()));

    // Count quotes
    let count = quote_repo.count().await.expect("Failed to count quotes");
    assert!(count >= 3);
}
