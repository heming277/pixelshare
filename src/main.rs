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

async fn save_file(user_id: Option<i64>, field: Part, pool: &SqlitePool) -> Result<String, Rejection> {
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

    // Insert file metadata into the database only if user_id is present
    if let Some(uid) = user_id {
        match sqlx::query("INSERT INTO files (user_id, file_name) VALUES (?, ?)")
            .bind(uid)
            .bind(&file_name)
            .execute(pool)
            .await
        {
            Ok(_) => eprintln!("File metadata inserted into database."),
            Err(e) => {
                eprintln!("Failed to insert file metadata: {:?}", e); // Log the error
                return Err(warp::reject::custom(InvalidJwt)); // Use a more appropriate error here
            }
        }
    }

    Ok(file_name)
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
    let file_name = save_file(user_id, part, &pool).await?;

    // Determine the success message
    let message = if user_id.is_some() {
        format!("File '{}' uploaded successfully by user", file_name)
    } else {
        format!("File '{}' uploaded successfully as a guest", file_name)
    };

    // Create the response object with the file name
    let response = UploadResponse { message, file_name };

    // Return a JSON response with status code 200 OK
    Ok(warp::reply::with_status(warp::reply::json(&response), StatusCode::OK))
}



async fn download_handler(_username: String, filename: String) -> Result<impl Reply, Rejection> {
    let file_path = PathBuf::from(format!("uploads/{}", sanitize(filename)));
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

    // Transform Vec<FileRecord> into Vec<serde_json::Value>
    let files: Vec<_> = file_records.into_iter().map(|record| {
        json!({ "name": record.file_name })
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


#[tokio::main]
async fn main() {
    dotenv().ok();
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
        .allow_methods(vec![Method::GET, Method::POST, Method::OPTIONS, Method::PUT]) 
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
    .or(sign_out_route)
    .or(static_files)
    .recover(handle_rejection) 
    .with(cors);

    // Start the Warp server
    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}