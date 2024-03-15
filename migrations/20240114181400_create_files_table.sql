-- Up
CREATE TABLE files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    file_name TEXT NOT NULL,
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    unique_id TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Down
DROP TABLE files;