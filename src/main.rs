use pixelshare::db;
use db::User;
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use serde::{Serialize, Deserialize};
use warp::{http::Response, Filter, Rejection, Reply};
use warp::http::StatusCode;
use warp::multipart::{FormData, Part};
use warp::http::Method;
use tokio::fs::File;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use std::path::PathBuf;
use futures::{StreamExt, TryStreamExt};
use sanitize_filename::sanitize;
use sqlx::SqlitePool;
use serde_json::json;
use bytes::Buf; 
use dotenv::dotenv;
use std::env;
use warp::reject::reject;
use tokio::fs;
use mime_guess::from_path;
use warp::hyper::Body;
//use image::{DynamicImage, GenericImageView, ImageFormat, imageops::FilterType};
use uuid::Uuid;
use percent_encoding::percent_decode_str;
//src/main.rs


// Define a custom error response
#[derive(Serialize)]
struct ErrorResponse {
    code: u16,
    message: String,
}



#[derive(Serialize)]
struct UploadResponse {
    message: String,
    file_name: String, 
    unique_id: String,
}

// Define a custom error type for upload errors
#[derive(Debug)]
struct UploadError;
impl warp::reject::Reject for UploadError {}


#[derive(Debug)]
struct InvalidJwt;
impl warp::reject::Reject for InvalidJwt {}

#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct DeleteFileQuery {
    unique_id: String,
    filename: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

fn with_db(pool: SqlitePool) -> impl Filter<Extract = (SqlitePool,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || pool.clone())
}






fn create_jwt(username: &str, secret: &[u8]) -> Result<String, jsonwebtoken::errors::Error> {
    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::hours(24))
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub: username.to_owned(),
        exp: expiration,
    };

    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret))
}

fn validate_jwt(token: &str, secret: &[u8]) -> Result<String, Rejection> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret),
        &Validation::new(Algorithm::HS256),
    ).map_err(|_| warp::reject::custom(InvalidJwt))?;

    Ok(token_data.claims.sub)
}


fn try_validate_jwt(token: &str, secret: &[u8]) -> Option<String> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret),
        &Validation::new(Algorithm::HS256),
    )
    .ok()
    .map(|token_data| token_data.claims.sub)
}


fn optional_auth(secret: Vec<u8>) -> impl Filter<Extract = (Option<String>,), Error = Rejection> + Clone {
    warp::header::optional::<String>("authorization")
        .map(move |authorization: Option<String>| {
            let secret = secret.clone();
            authorization.and_then(|value| {
                value
                    .strip_prefix("Bearer ")
                    .and_then(|token| try_validate_jwt(token, &secret))
            })
        })
}



fn with_auth(secret: Vec<u8>) -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
    warp::header::<String>("authorization")
        .and_then(move |value: String| {
            let secret = secret.clone();
            async move {
                let token = value.strip_prefix("Bearer ").ok_or_else(|| warp::reject::custom(InvalidJwt))?;
                validate_jwt(token, &secret).map_err(|_| warp::reject::custom(InvalidJwt))
            }
        })
}





async fn register_handler(body: RegisterRequest, pool: SqlitePool) -> Result<impl Reply, Rejection> {
    match User::create(&body.username, &body.password, &pool).await {
        Ok(_) => Ok(warp::reply::with_status(
            warp::reply::json(&json!({"message": "User created successfully"})),
            StatusCode::CREATED,
        )),
        Err(e) => {
            eprintln!("Failed to create user: {}", e); // Log the error
            // Return a generic error response
            Ok(warp::reply::with_status(
                warp::reply::json(&json!({"error": "Failed to create user"})),
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        },
    }
}

async fn login_handler(body: LoginRequest, pool: SqlitePool, secret_key: String) -> Result<impl Reply, Rejection> {
    match User::find_by_username(&body.username, &pool).await {
        Ok(user) => {
            if user.verify_password(&body.password) {
                let token = create_jwt(&body.username, secret_key.as_bytes()).map_err(|_| warp::reject::custom(InvalidJwt))?;
                Ok(warp::reply::with_status(
                    warp::reply::json(&json!({"token": token})),
                    StatusCode::OK,
                ))
            } else {
                Ok(warp::reply::with_status(
                    warp::reply::json(&json!({"message": "Unauthorized"})),
                    StatusCode::UNAUTHORIZED,
                ))
            }
        }
        Err(e) => {
            eprintln!("Failed to find user: {}", e); // Log the error
            Ok(warp::reply::with_status(
                warp::reply::json(&json!({"message": "Unauthorized"})),
                StatusCode::UNAUTHORIZED,
            ))
        },
    }
}


async fn sign_out_handler() -> Result<impl Reply, Rejection> {
    Ok(warp::reply::with_status(
        warp::reply::json(&json!({"message": "Signed out successfully"})),
        StatusCode::OK,
    ))
}

async fn save_file(user_id: Option<i64>, field: Part, pool: &SqlitePool) -> Result<(String, String), Rejection> {
    let file_name = field.filename().map(|name| sanitize(name.to_string())).unwrap_or_else(|| "file".to_string());
    let file_path = PathBuf::from(format!("uploads/{}", file_name));

    fs::create_dir_all("uploads").await.map_err(|e| {
        eprintln!("Failed to create uploads directory: {:?}", e);
        warp::reject::custom(InvalidJwt) // 
    })?;

    // Log the file path where the file will be saved
    eprintln!("Saving file to {:?}", file_path);

    let mut file = match File::create(&file_path).await {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to create file: {:?}", e); // Log the error
            return Err(warp::reject::custom(InvalidJwt)); // Use a more appropriate error here
        }
    };

  
    let mut stream = field.stream();
    while let Some(chunk) = stream.next().await {
        let data = match chunk {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Error reading chunk: {:?}", e); // Log the error
                return Err(warp::reject::custom(InvalidJwt)); // Use a more appropriate error here
            }
        };
        if let Err(e) = file.write_all(&data.chunk()).await {
            eprintln!("Error writing to file: {:?}", e); // Log the error
            return Err(warp::reject::custom(InvalidJwt)); // Use a more appropriate error here
        }
    }

    // Log successful file save
    eprintln!("File saved successfully: {:?}", file_path);

    let unique_id = Uuid::new_v4().to_string();

    // Insert file metadata into the database only if user_id is present
    if let Some(uid) = user_id {
        match sqlx::query("INSERT INTO files (user_id, file_name, unique_id) VALUES (?, ?, ?)")
            .bind(uid)
            .bind(&file_name)
            .bind(&unique_id) // Bind the unique_id here
            .execute(pool)
            .await
        {
            Ok(_) => eprintln!("File metadata inserted into database."),
            Err(e) => {
                eprintln!("Failed to insert file metadata: {:?}", e);
                return Err(warp::reject::custom(InvalidJwt)); // Consider using a more specific error
            }
        }
    }

    Ok((file_name, unique_id))
}


async fn upload_handler(form: FormData, username: Option<String>, pool: SqlitePool) -> Result<impl Reply, Rejection> {
    // Attempt to find the user by username and log any errors
    let user_id = if let Some(user_name) = username {
        match User::find_by_username(&user_name, &pool).await {
            Ok(user) => Some(user.id),
            Err(e) => {
                eprintln!("Error finding user by username: {:?}", e);
                return Err(reject()); // Replace with an appropriate rejection
            }
        }
    } else {
        None
    };

    // Process a single file from the form data stream
    let mut parts = form.into_stream();
    let part = match parts.try_next().await {
        Ok(Some(part)) => part,
        Ok(None) => return Err(reject()), 
        Err(_) => return Err(reject()), 
    };

    // Save the file and get the file name
    let (file_name, unique_id) = save_file(user_id, part, &pool).await?;


    // Determine the success message
    let message = if user_id.is_some() {
        format!("File '{}' uploaded successfully by user", file_name)
    } else {
        format!("File '{}' uploaded successfully as a guest", file_name)
    };

    // Create the response object with the file name
    let response = UploadResponse { message, file_name, unique_id }; 
    // Return a JSON response with status code 200 OK
    Ok(warp::reply::with_status(warp::reply::json(&response), StatusCode::OK))
}

async fn share_file_handler(unique_id: String, pool: SqlitePool) -> Result<impl Reply, Rejection> {
    let file_data = sqlx::query!("SELECT file_name FROM files WHERE unique_id = ?", unique_id)
        .fetch_one(&pool)
        .await
        .map_err(|_| warp::reject::custom(InvalidJwt))?; // Adjust error handling as needed

    let file_path = PathBuf::from(format!("uploads/{}", file_data.file_name));
    let mime_type = from_path(&file_path).first_or_octet_stream();

    let mut file = File::open(file_path).await.map_err(|_| warp::reject::custom(InvalidJwt))?;
    let mut contents = vec![];
    file.read_to_end(&mut contents).await.map_err(|_| warp::reject::custom(InvalidJwt))?;

    Ok(Response::builder()
        .header("Content-Type", mime_type.to_string())
        .body(Body::from(contents)))
}


async fn download_handler(_username: String, filename: String) -> Result<impl Reply, Rejection> {
    
    
    let decoded_filename = percent_decode_str(&filename)
        .decode_utf8_lossy()
        .into_owned();

    let sanitized_filename = sanitize(decoded_filename);
        
    let file_path = PathBuf::from(format!("uploads/{}", sanitized_filename));
    let mime_type = from_path(&file_path).first_or_octet_stream(); // Guess MIME type

    let mut file = File::open(file_path).await.map_err(|_| warp::reject::custom(InvalidJwt))?;
    let mut contents = vec![];
    file.read_to_end(&mut contents).await.map_err(|_| warp::reject::custom(InvalidJwt))?;

    Ok(Response::builder()
        .header("Content-Type", mime_type.to_string())
        .body(Body::from(contents)))
}


async fn list_files_handler(username: String, pool: SqlitePool) -> Result<impl Reply, Rejection> {
    let user = User::find_by_username(&username, &pool).await.map_err(|_| warp::reject::custom(InvalidJwt))?;
    let file_records = User::get_user_files(user.id, &pool).await.map_err(|_| warp::reject::custom(InvalidJwt))?;

    // Ensure that your FileRecord struct or the equivalent has a `unique_id` field
    // Transform Vec<FileRecord> into Vec<serde_json::Value>, including the unique_id
    let files: Vec<_> = file_records.into_iter().map(|record| {
        json!({
            "name": record.file_name,
            "unique_id": record.unique_id // Include the unique_id in the response
        })
    }).collect();

    Ok(warp::reply::json(&files))
}

async fn handle_rejection(err: Rejection) -> Result<impl Reply, std::convert::Infallible> {
    let (code, message) = if err.is_not_found() {
        (StatusCode::NOT_FOUND, "Not Found")
    } else if err.find::<warp::reject::MethodNotAllowed>().is_some() {
        (StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed")
    } else if err.find::<UploadError>().is_some() {
        (StatusCode::BAD_REQUEST, "Error processing upload")
    } else {
        eprintln!("Unhandled error: {:?}", err);
        (StatusCode::INTERNAL_SERVER_ERROR, "Unhandled error")
    };

    let json = warp::reply::json(&ErrorResponse {
        code: code.as_u16(),
        message: message.to_string(),
    });

    Ok(warp::reply::with_status(json, code))
}


fn with_user_id(pool: SqlitePool, secret: Vec<u8>) -> impl Filter<Extract = (i64,), Error = Rejection> + Clone {
    warp::header::<String>("authorization")
        .and_then(move |value: String| {
            let secret_cloned = secret.clone();
            let pool_cloned = pool.clone();
            async move {
                let token = value.strip_prefix("Bearer ").ok_or_else(|| warp::reject::custom(InvalidJwt))?;
                let username = validate_jwt(token, &secret_cloned).map_err(|_| warp::reject::custom(InvalidJwt))?;
                
                // Fetch user ID from the database using the username
                let user_id = User::find_by_username(&username, &pool_cloned).await
                    .map_err(|_| warp::reject::custom(InvalidJwt))?
                    .id;
                
                Ok::<_, warp::Rejection>(user_id)
            }
        })
}


async fn delete_file_handler(query_params: DeleteFileQuery, user_id: i64, pool: SqlitePool) -> Result<impl warp::Reply, warp::Rejection> {
    let unique_id = &query_params.unique_id;
    let filename = &query_params.filename;

    log::info!("Attempting to delete file with unique_id: {} for user_id: {}", unique_id, user_id);

    // Decode and sanitize the filename to ensure it's safe for use in file paths
    let decoded_filename = percent_decode_str(filename)
        .decode_utf8_lossy()
        .into_owned();
    let sanitized_filename = sanitize(decoded_filename);

    // Directly proceed to delete the file record from the SQLite database for the specific unique_id and user_id
    let num_deleted = sqlx::query!(
        "DELETE FROM files WHERE unique_id = ? AND user_id = ?",
        unique_id,
        user_id
    )
    .execute(&pool)
    .await
    .map_err(|_| warp::reject::custom(UploadError))?
    .rows_affected();

    // Check if a file was actually deleted
    if num_deleted == 0 {
        // No file was deleted, possibly because it didn't exist for this user
        return Err(warp::reject::custom(InvalidJwt)); // Consider using a more appropriate error or custom rejection
    }

    // Check if there are no more files with the same name in the database
    let files_with_same_name = sqlx::query!(
        "SELECT COUNT(*) as count FROM files WHERE file_name = ?",
        sanitized_filename
    )
    .fetch_one(&pool)
    .await
    .map_err(|_| warp::reject::custom(UploadError))?
    .count;

    if files_with_same_name == 0 {
        // If the file record was successfully deleted and no other files with the same name exist, proceed to delete the file from the filesystem
        let file_path = PathBuf::from(format!("uploads/{}", sanitized_filename));
        tokio::fs::remove_file(&file_path).await.map_err(|_| warp::reject::custom(UploadError))?;
    }

    Ok(warp::reply::with_status(
        warp::reply::json(&json!({"message": "File deleted successfully"})),
        StatusCode::OK,
    ))
}


#[tokio::main]
async fn main() {
    dotenv().ok();
    env_logger::init(); 
    let secret_key = env::var("SECRET_KEY").expect("SECRET_KEY must be set");

    let secret_key_for_filter = secret_key.clone();
    let secret_key_filter = warp::any().map(move || secret_key_for_filter.clone());

    let secret_key_bytes = secret_key.into_bytes();
    let optional_auth_filter = optional_auth(secret_key_bytes.clone());
    let with_auth_filter = with_auth(secret_key_bytes.clone());
   
    let sign_out_route = warp::path("sign_out")
        .and(warp::post())
        .and_then(sign_out_handler);
    
    let pool = SqlitePool::connect("sqlite:mydb.sqlite").await.expect("Failed to connect to the database");

    let cors = warp::cors()
        .allow_any_origin()
        .allow_headers(vec!["Content-Type", "User-Agent", "Authorization"])
        .allow_methods(vec![Method::GET, Method::POST, Method::OPTIONS, Method::PUT, Method::DELETE]) // Include DELETE here
        .build();

    let register_route = warp::path("register")
        .and(warp::post())
        .and(warp::body::json::<RegisterRequest>())
        .and(with_db(pool.clone()))
        .and_then(register_handler);

    let login_route = warp::path("login")
        .and(warp::post())
        .and(warp::body::json::<LoginRequest>())
        .and(with_db(pool.clone()))
        .and(secret_key_filter.clone()) 
        .and_then(login_handler);

    let upload_route = warp::path("upload")
        .and(warp::post())
        .and(warp::multipart::form())
        .and(optional_auth_filter.clone()) 
        .and(with_db(pool.clone()))
        .and_then(upload_handler);

    let download_route = warp::path("files") // This should match the client-side path
        .and(warp::get())
        .and(with_auth_filter.clone()) 
        .and(warp::path::param()) // This captures the filename parameter
        .and_then(download_handler);

    let list_files_route = warp::path("list_files")
        .and(warp::get())
        .and(with_auth_filter.clone()) 
        .and(with_db(pool.clone()))
        .and_then(list_files_handler);

    let delete_route = warp::path("delete")
        .and(warp::delete())
        .and(warp::query::<DeleteFileQuery>()) // Using the struct here
        .and(with_user_id(pool.clone(), secret_key_bytes.clone()))
        .and(with_db(pool.clone()))
        .and_then(delete_file_handler);


    let share_route = warp::path("share")
        .and(warp::get())
        .and(warp::path::param::<String>())
        .and(with_db(pool.clone()))
        .and_then(share_file_handler);
    
    // Serve static files from the frontend directory
    let static_files = warp::fs::dir("frontend");

    // Serve index.html at the root path
    let index_route = warp::path::end()
        .and(warp::get())
        .and(warp::fs::file("frontend/index.html"));

    // Combine all the routes
    let routes = index_route
    .or(register_route)
    .or(login_route)
    .or(upload_route)
    .or(download_route)
    .or(list_files_route)
    .or(delete_route)
    .or(sign_out_route)
    .or(share_route)
    .or(static_files)
    .recover(handle_rejection) 
    .with(cors);

    // Start the Warp server
    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}