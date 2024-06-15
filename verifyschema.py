def add_login_attempts_column():
    conn = get_db_connection()
    conn.execute('ALTER TABLE users ADD COLUMN login_attempts INTEGER DEFAULT 0')
    conn.commit()
    conn.close()

# Run this function once to update the database schema
add_login_attempts_column()
