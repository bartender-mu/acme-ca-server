CREATE TYPE web_group AS ENUM ('admin', 'readonly');

CREATE TABLE web_users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_bcrypt TEXT NOT NULL,
    group_name web_group NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);
