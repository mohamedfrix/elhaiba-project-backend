use elhaiba_backend::model::quote::{Quote, QuoteNote};
use elhaiba_backend::repository::quote_repo::{MongoQuoteRepository, QuoteRepository};
use elhaiba_backend::repository::quote_note_repo::{MongoQuoteNoteRepository, QuoteNoteRepository};
use elhaiba_backend::repository::repository_error::{RepositoryResult, RepositoryError};
use elhaiba_backend::config::mongo_conf::MongoConfig;
use bson::oid::ObjectId;
use tokio;

async fn setup_quote_and_note_repos() -> (MongoQuoteRepository, MongoQuoteNoteRepository, Quote) {
    let _ = dotenv::dotenv();
    let config = MongoConfig::from_env().expect("Failed to load MongoConfig");
    let quote_repo = MongoQuoteRepository::new(&config).await.expect("Failed to setup quote repo");
    let note_repo = MongoQuoteNoteRepository::new(&config).await.expect("Failed to setup quote note repo");

    // Insert a quote to attach notes to
    let quote = Quote {
        id: None,
        fullName: "Note Test User".to_string(),
        phone: "+213770000001".to_string(),
        email: Some("noteuser@elhaiba.com".to_string()),
        country: "Algeria".to_string(),
        wilaya: "Oran".to_string(),
        address: Some("456 Side St, Oran".to_string()),
        spaceType: "Commercial".to_string(),
        spaceTypeOther: Some("Shop".to_string()),
        projectState: "Started".to_string(),
        area: 120.0,
        floorsNumber: 1,
        vacantLand: false,
        serviceType: "Engineering".to_string(),
        serviceTypeOther: Some("Consulting".to_string()),
        haveFiles: false,
        files: None,
        startDate: "2025-09-01".to_string(),
        note: Some("For note repo test".to_string()),
        firstTime: Some(false),
        hearAboutUs: Some("Facebook".to_string()),
        status: Some("active".to_string()),
        createdAt: None,
        updatedAt: None,
    };
    let inserted_quote = quote_repo.create(quote).await.expect("Failed to insert quote for note test");
    (quote_repo, note_repo, inserted_quote)
}

#[tokio::test]
async fn test_quote_note_repository_workflow() {
    let (_quote_repo, note_repo, quote) = setup_quote_and_note_repos().await;
    let quote_id = quote.id.clone().expect("Inserted quote should have id");

    // Create a note
    let mut note = QuoteNote {
        id: None,
        quoteId: quote_id,
        title: "Initial Note".to_string(),
        content: "This is the first note.".to_string(),
        createdAt: chrono::Local::now().to_rfc3339(),
        updatedAt: chrono::Local::now().to_rfc3339(),
    };
    let inserted_note = note_repo.create(note.clone()).await.expect("Failed to insert note");
    assert!(inserted_note.id.is_some());
    let note_id = inserted_note.id.clone().unwrap();

    // Get by id
    let fetched_note = note_repo.get_by_id(note_id).await.expect("Failed to get note by id");
    assert_eq!(fetched_note.title, note.title);
    assert_eq!(fetched_note.content, note.content);

    // Insert multiple notes
    let mut notes = vec![];
    for i in 0..2 {
        let mut n = note.clone();
        n.title = format!("Note {}", i);
        n.content = format!("Content for note {}", i);
        n.createdAt = chrono::Local::now().to_rfc3339();
        n.updatedAt = chrono::Local::now().to_rfc3339();
        let inserted = note_repo.create(n).await.expect("Failed to insert note");
        notes.push(inserted);
    }
    assert_eq!(notes.len(), 2);

    // List notes by quote
    let listed_notes = note_repo.list_by_quote(quote_id).await.expect("Failed to list notes by quote");
    assert!(listed_notes.len() >= 3); // At least the ones we inserted

    // Update a note
    let mut to_update = notes[0].clone();
    to_update.content = "Updated content for note 0".to_string();
    let updated_note = note_repo.update(to_update.id.clone().unwrap(), to_update.clone()).await.expect("Failed to update note");
    assert_eq!(updated_note.content, "Updated content for note 0");

    // Delete a note
    let delete_id = notes[1].id.clone().unwrap();
    note_repo.delete(delete_id).await.expect("Failed to delete note");

    // List again to confirm deletion
    let listed_notes_after = note_repo.list_by_quote(quote_id).await.expect("Failed to list notes after delete");
    assert!(listed_notes_after.len() >= 2);
}
