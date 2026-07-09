CREATE DATABASE IF NOT EXISTS mailpanel CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE mailpanel;

CREATE TABLE IF NOT EXISTS panel_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(128) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('superadmin', 'admin', 'viewer', 'user') NOT NULL DEFAULT 'viewer',
    mailbox VARCHAR(255) NULL,
    display_name VARCHAR(255) NOT NULL DEFAULT '',
    active TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_log (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    username VARCHAR(128) NOT NULL,
    action VARCHAR(64) NOT NULL,
    resource VARCHAR(128) NOT NULL DEFAULT '',
    details TEXT NULL,
    ip_address VARCHAR(45) NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_created (created_at)
);

CREATE TABLE IF NOT EXISTS mail_log_entries (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    logged_at DATETIME NOT NULL,
    service VARCHAR(32) NOT NULL,
    level VARCHAR(16) NOT NULL DEFAULT 'info',
    queue_id VARCHAR(32) NULL,
    mail_from VARCHAR(255) NULL,
    mail_to VARCHAR(255) NULL,
    status VARCHAR(64) NULL,
    spam_score DECIMAL(5,2) NULL,
    message TEXT NOT NULL,
    raw_line TEXT NOT NULL,
    INDEX idx_logged_at (logged_at),
    INDEX idx_queue_id (queue_id),
    INDEX idx_mail_from (mail_from),
    INDEX idx_mail_to (mail_to)
);

CREATE TABLE IF NOT EXISTS mail_groups (
    address VARCHAR(255) PRIMARY KEY,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
