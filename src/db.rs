use sqlx::{Error as SqlxError, SqlitePool};
use sqlx::FromRow;
use bcrypt::{BcryptError, hash, DEFAULT_COST};
use thiserror::Error;
use bcrypt::verify;
use serde::{Deserialize, Serialize};


// src/db.rs
#[derive(Error, Debug)]
pub enum UserCreationError {
    #[error("bcrypt error: {0}")]
    BcryptError(#[from] BcryptError),
    #[error("database error: {0}")]
    DatabaseError(#[from] SqlxError),
}

#[derive(FromRow)]
pub struct User {
    pub id: i64, 
    pub username: String,
    pub password_hash: String,
}

#[derive(Serialize, Deserialize)] 
pub struct FileRecord {
    pub file_name: String,
    pub upload_date: Option<chrono::NaiveDateTime>,
}

impl User {
    pub async fn create(username: &str, password: &str, pool: &SqlitePool) -> Result<Self, UserCreationError> {
        let password_hash = hash(password, DEFAULT_COST).map_err(UserCreationError::BcryptError)?;
        let result = sqlx::query("INSERT INTO users (username, password_hash) VALUES (?, ?)")
            .bind(username)
            .bind(&password_hash)
            .execute(pool)
            .await?;

        // Retrieve the last inserted id
        let user_id = result.last_insert_rowid();

        Ok(User {
            id: user_id, // Use the retrieved id here
            username: username.to_owned(),
            password_hash,
        })
    }

    pub async fn find_by_username(username: &str, pool: &SqlitePool) -> Result<Self, SqlxError> {
        let row = sqlx::query_as::<_, User>("SELECT id, username, password_hash FROM users WHERE username = ?")
            .bind(username)
            .fetch_one(pool)
            .await?;

        Ok(row)
    }

    pub fn verify_password(&self, password: &str) -> bool {
        verify(password, &self.password_hash).unwrap_or(false)
    }

    pub async fn get_user_files(user_id: i64, pool: &SqlitePool) -> Result<Vec<FileRecord>, sqlx::Error> {
        let files = sqlx::query_as!(
            FileRecord,
            "SELECT file_name, upload_date FROM files WHERE user_id = ?",
            user_id
        )
        .fetch_all(pool)
        .await?;

        Ok(files)
    }



}





