import sqlite3


def add_constraints(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Add unique constraints if not present
    cursor.execute("PRAGMA table_info(users)")
    columns = cursor.fetchall()
    column_names = [col[1] for col in columns]
    constraints = cursor.execute("PRAGMA index_list(users)").fetchall()

    if 'email' in column_names and not any('email_unique' in con for con in constraints):
        cursor.execute("CREATE UNIQUE INDEX email_unique ON users(email)")
    if 'username' in column_names and not any('username_unique' in con for con in constraints):
        cursor.execute("CREATE UNIQUE INDEX username_unique ON users(username)")

    # Ensure NOT NULL constraints are in place for necessary columns
    if 'password_hash' in column_names:
        cursor.execute("ALTER TABLE users RENAME TO old_users")
        cursor.execute('''
            CREATE TABLE users (
                user_id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                first_name TEXT,
                last_name TEXT,
                middle_name TEXT,
                email TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                UNIQUE(email),
                UNIQUE(username)
            )
        ''')
        cursor.execute('''
            INSERT INTO users (user_id, username, first_name, last_name, middle_name, email, password_hash, role)
            SELECT user_id, username, first_name, last_name, middle_name, email, password_hash, role FROM old_users
        ''')
        cursor.execute("DROP TABLE old_users")

    conn.commit()
    cursor.close()
    conn.close()


if __name__ == "__main__":
    db_path = 'instance/DMSDB.db'
    add_constraints(db_path)
    print("Constraints added successfully.")
