## Database commands

1. Create database
```sql
CREATE DATABASE kkticketing;
```

2. Create user table
```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    passwd VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

3. Create tickets table
```sql
CREATE TABLE tickets (
    ticket_id VARCHAR(15) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    id_no VARCHAR(30) NOT NULL,
    phone_no VARCHAR(15),
    email VARCHAR(50) NOT NULL,
    is_vip BOOLEAN NOT NULL,
    mail_sent BOOLEAN DEFAULT FALSE,
    issued_by INT,
    issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (issued_by) REFERENCES users(id)
);
```