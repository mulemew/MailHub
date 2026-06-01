-- MailHub D1 Database Schema

-- Mailboxes (email addresses)
CREATE TABLE IF NOT EXISTS mailboxes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  address TEXT NOT NULL UNIQUE,
  local_part TEXT NOT NULL,
  domain TEXT NOT NULL,
  is_auto_created INTEGER DEFAULT 0,
  is_pinned INTEGER DEFAULT 0,
  is_favorite INTEGER DEFAULT 0,
  forward_to TEXT DEFAULT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Messages (received emails)
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mailbox_id INTEGER NOT NULL,
  sender TEXT NOT NULL,
  to_addr TEXT NOT NULL DEFAULT '',
  subject TEXT NOT NULL DEFAULT '',
  preview TEXT DEFAULT '',
  html_content TEXT DEFAULT '',
  text_content TEXT DEFAULT '',
  verification_code TEXT DEFAULT NULL,
  eml_r2_key TEXT DEFAULT '',
  is_read INTEGER DEFAULT 0,
  is_deleted INTEGER DEFAULT 0,
  deleted_at TEXT DEFAULT NULL,
  received_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE
);

-- Attachments (content stored in R2, metadata in D1)
CREATE TABLE IF NOT EXISTS attachments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  message_id INTEGER NOT NULL,
  filename TEXT NOT NULL,
  content_type TEXT DEFAULT '',
  size INTEGER DEFAULT 0,
  r2_key TEXT DEFAULT '',
  content TEXT DEFAULT '',
  FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
);

-- Sent emails
CREATE TABLE IF NOT EXISTS sent_emails (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  from_addr TEXT NOT NULL,
  from_name TEXT DEFAULT '',
  to_addrs TEXT NOT NULL,
  cc_addrs TEXT DEFAULT '',
  bcc_addrs TEXT DEFAULT '',
  subject TEXT NOT NULL DEFAULT '',
  html_content TEXT DEFAULT '',
  text_content TEXT DEFAULT '',
  resend_id TEXT DEFAULT '',
  send_provider TEXT DEFAULT 'resend',
  status TEXT DEFAULT 'sent',
  is_deleted INTEGER DEFAULT 0,
  deleted_at TEXT DEFAULT NULL,
  status_updated_at TEXT DEFAULT NULL,
  delivery_error TEXT DEFAULT NULL,
  is_favorite INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Settings (key-value store)
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- Sent email attachments (content stored in R2, metadata in D1)
CREATE TABLE IF NOT EXISTS sent_attachments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sent_email_id INTEGER NOT NULL,
  filename TEXT NOT NULL,
  content_type TEXT DEFAULT '',
  size INTEGER DEFAULT 0,
  r2_key TEXT DEFAULT '',
  FOREIGN KEY (sent_email_id) REFERENCES sent_emails(id) ON DELETE CASCADE
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_mailboxes_address ON mailboxes(address);
CREATE INDEX IF NOT EXISTS idx_mailboxes_domain ON mailboxes(domain);
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_id ON messages(mailbox_id);
CREATE INDEX IF NOT EXISTS idx_messages_received_at ON messages(received_at DESC);
CREATE INDEX IF NOT EXISTS idx_attachments_message_id ON attachments(message_id);
CREATE INDEX IF NOT EXISTS idx_sent_emails_from ON sent_emails(from_addr);
CREATE INDEX IF NOT EXISTS idx_sent_emails_created ON sent_emails(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_deleted ON messages(is_deleted);
CREATE INDEX IF NOT EXISTS idx_sent_deleted ON sent_emails(is_deleted);
CREATE INDEX IF NOT EXISTS idx_sent_attachments_email ON sent_attachments(sent_email_id);
CREATE INDEX IF NOT EXISTS idx_messages_favorite ON messages(is_favorite);
