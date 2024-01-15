// tests/user_flow.rs
//integration testing
use reqwest::multipart::{Form, Part};
use tokio;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use pixelshare::db::FileRecord;
use serde::{Deserialize, Serialize};



#[derive(Serialize)]
struct RegisterRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct LoginResponse {
    token: String,
}



#[tokio::test]
async fn test_complete_user_flow() {
    let client = reqwest::Client::new();
    let base_url = "http://localhost:3030";

    // Generate a unique username to avoid conflicts with existing users
    let unique_username = format!("testuser_{}", uuid::Uuid::new_v4());

    // Test user signup
    let signup_response = client
        .post(&format!("{}/register", base_url))
        .json(&RegisterRequest {
            username: unique_username.clone(),
            password: "password123".to_string(),
        })
        .send()
        .await
        .expect("Failed to execute request.");

    assert!(signup_response.status().is_success());

    // Test user login
    let login_response = client
        .post(&format!("{}/login", base_url))
        .json(&LoginRequest {
            username: unique_username,
            password: "password123".to_string(),
        })
        .send()
        .await
        .expect("Failed to execute request.");

    assert!(login_response.status().is_success());

    let login_response_body = login_response
        .json::<LoginResponse>()
        .await
        .expect("Failed to parse login response.");

    let token = login_response_body.token;
    assert!(!token.is_empty());

    // Test file upload
    let mut file = File::open("/Users/hemingliu/Documents/pixelshare/yesterday.txt").await.expect("Failed to open file");
    let mut file_bytes = Vec::new();
    file.read_to_end(&mut file_bytes).await.expect("Failed to read file");

    let file_part = Part::bytes(file_bytes)
        .file_name("yesterday.txt")
        .mime_str("text/plain")
        .expect("Failed to create file part");

    let form = Form::new().part("file", file_part);

    let upload_response = client
        .post(&format!("{}/upload", base_url))
        .bearer_auth(&token)
        .multipart(form)
        .send()
        .await;

    if let Err(e) = upload_response {
        // Print out the error if the request failed
        println!("Upload request failed: {:?}", e);
    } else {
        let upload_response = upload_response.unwrap();
        let status = upload_response.status();
        let body = upload_response.text().await.unwrap_or_else(|_| "Failed to read response body".to_string());

        println!("Status code: {}", status);
        println!("Response body: {:?}", body);
        assert!(status.is_success());
    }
    // Test file download
    let file_name = "yesterday.txt";
    let download_response = client
        .get(&format!("{}/download/{}", base_url, file_name))
        .bearer_auth(&token)
        .send()
        .await
        .expect("Failed to execute request.");

    assert!(download_response.status().is_success());

    // Optional: Check the contents of the file
    let contents = download_response
        .bytes()
        .await
        .expect("Failed to read file contents");


    assert_eq!(contents.as_ref(), b"Expected contents" as &[u8]);

    // Test list files
    let list_files_response = client
        .get(&format!("{}/list_files", base_url))
        .bearer_auth(&token)
        .send()
        .await
        .expect("Failed to execute request.");

    assert!(list_files_response.status().is_success());

    let files: Vec<FileRecord> = list_files_response
        .json()
        .await
        .expect("Failed to parse list files response");

    assert!(files.iter().any(|file| file.file_name == "yesterday.txt"));
}

















#[tokio::test]
async fn test_user_signup_and_login() {
    let client = reqwest::Client::new();
    let base_url = "http://localhost:3030"; 

    // Test user signup.
    let signup_response = client
        .post(&format!("{}/register", base_url))
        .json(&RegisterRequest {
            username: "testuser".to_string(),
            password: "password123".to_string(),
        })
        .send()
        .await
        .expect("Failed to execute request.");

    assert!(signup_response.status().is_success());

    // Test user login.
    let login_response = client
        .post(&format!("{}/login", base_url))
        .json(&LoginRequest {
            username: "testuser".to_string(),
            password: "password123".to_string(),
        })
        .send()
        .await
        .expect("Failed to execute request.");

    assert!(login_response.status().is_success());

    let login_response_body = login_response
        .json::<LoginResponse>()
        .await
        .expect("Failed to parse login response.");

    assert!(!login_response_body.token.is_empty());
}



#[tokio::test]
async fn test_file_upload() {
    let client = reqwest::Client::new();
    let base_url = "http://localhost:3030"; 

    // First, log in to get a token
    let login_response = client
        .post(&format!("{}/login", base_url))
        .json(&LoginRequest {
            username: "testuser".to_string(),
            password: "password123".to_string(),
        })
        .send()
        .await
        .expect("Failed to execute request.");

    assert!(login_response.status().is_success());

    let login_response_body = login_response
        .json::<LoginResponse>()
        .await
        .expect("Failed to parse login response.");

    let token = login_response_body.token;
    assert!(!token.is_empty());
    println!("Received token: {:?}", token);

        // Read the file into a byte vector
    let mut file = File::open("/Users/hemingliu/Documents/pixelshare/yesterday.txt").await.expect("Failed to open file");
    let mut file_bytes = Vec::new();
    file.read_to_end(&mut file_bytes).await.expect("Failed to read file");

    // Create a multipart form with the file part
    let file_part = Part::bytes(file_bytes)
        .file_name("yesterday.txt") 
        .mime_str("text/plain") 
        .expect("Failed to create file part");

    let form = Form::new()
        .part("file", file_part); 

    // Send the multipart form in the request
    let upload_response = client
        .post(&format!("{}/upload", base_url))
        .bearer_auth(token)
        .multipart(form)
        .send()
        .await
        .expect("Failed to execute request.");

    let status = upload_response.status();
    let body = upload_response.text().await.unwrap();

    println!("Status code: {}", status);
    println!("Response body: {:?}", body);
    assert!(status.is_success());
}




#[tokio::test]
async fn test_file_download() {
    let client = reqwest::Client::new();
    let base_url = "http://localhost:3030"; 

    let login_response = client
        .post(&format!("{}/login", base_url))
        .json(&LoginRequest {
            username: "testuser".to_string(),
            password: "password123".to_string(),
        })
        .send()
        .await
        .expect("Failed to execute request.");

    let login_response_body = login_response
        .json::<LoginResponse>()
        .await
        .expect("Failed to parse login response.");

    let token = login_response_body.token;

    // Use the token to download the file
    let file_name = "yesterday.txt"; 
    let download_response = client
        .get(&format!("{}/download/{}", base_url, file_name))
        .bearer_auth(token)
        .send()
        .await
        .expect("Failed to execute request.");

    assert!(download_response.status().is_success());

    // Optional check the contents of the file
    let contents = download_response
        .bytes()
        .await
        .expect("Failed to read file contents");

    assert_eq!(contents.as_ref(), b"opwiejfpoijefpoijwefpoijwepofijwefp" as &[u8]);
}

#[tokio::test]
async fn test_list_files() {

    let client = reqwest::Client::new();
    let base_url = "http://localhost:3030"; 
    
    let login_response = client
        .post(&format!("{}/login", base_url))
        .json(&LoginRequest {
            username: "testuser".to_string(),
            password: "password123".to_string(),
        })
        .send()
        .await
        .expect("Failed to execute request.");

    let login_response_body = login_response
        .json::<LoginResponse>()
        .await
        .expect("Failed to parse login response.");

    let token = login_response_body.token;

    // Use the token to get the list of files
    let list_files_response = client
        .get(&format!("{}/list_files", base_url))
        .bearer_auth(token)
        .send()
        .await
        .expect("Failed to execute request.");

    assert!(list_files_response.status().is_success());

    // Parse the response and check if the uploaded file is in the list
    let files: Vec<FileRecord> = list_files_response
        .json()
        .await
        .expect("Failed to parse list files response");

    assert!(files.iter().any(|file| file.file_name == "yesterday.txt")); 
}




