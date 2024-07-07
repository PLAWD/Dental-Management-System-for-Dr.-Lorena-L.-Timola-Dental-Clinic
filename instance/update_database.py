def init_db():
    conn = sqlite3.connect('instance/DMSDB.db')
    cursor = conn.cursor()

    # Drop tables if they exist
    cursor.execute('DROP TABLE IF EXISTS Inventory')
    cursor.execute('DROP TABLE IF EXISTS Category')
    cursor.execute('DROP TABLE IF EXISTS Item')
    cursor.execute('DROP TABLE IF EXISTS Price')
    cursor.execute('DROP TABLE IF EXISTS Roles')
    cursor.execute('DROP TABLE IF EXISTS Seller')
    cursor.execute('DROP TABLE IF EXISTS Variation')

    # Create tables
    cursor.execute('''
    CREATE TABLE "Inventory" (
        "inventory_id" INTEGER PRIMARY KEY AUTOINCREMENT,
        "item_id" INTEGER,
        "stocked_quantity" INTEGER,
        "seller_id" INTEGER,
        "exact_price" REAL,
        "low_stock_threshold" INTEGER,
        "date_added" DATE,
        "time_added" TIME,
        "added_by" INTEGER,
        "added_by_id" INTEGER,
        "added_by_role" TEXT,
        "is_disabled" INTEGER DEFAULT 0,
        FOREIGN KEY("seller_id") REFERENCES "Seller"("seller_id"),
        FOREIGN KEY("item_id") REFERENCES "Item"("item_id"),
        FOREIGN KEY("added_by_id") REFERENCES "Item"("item_id")
    )''')

    cursor.execute('''
    CREATE TABLE "Category" (
        "category_id" INTEGER PRIMARY KEY AUTOINCREMENT,
        "category_name" TEXT NOT NULL
    )''')

    cursor.execute('''
    CREATE TABLE "Item" (
        "item_id" INTEGER PRIMARY KEY AUTOINCREMENT,
        "item_name" TEXT NOT NULL,
        "category_id" INTEGER,
        "variation_id" INTEGER,
        "variation_description" TEXT,
        "unique_item_id" TEXT,
        FOREIGN KEY("category_id") REFERENCES "Category"("category_id"),
        FOREIGN KEY("variation_id") REFERENCES "Variation"("variation_id")
    )''')

    cursor.execute('''
    CREATE TABLE "Price" (
        "price_id" INTEGER PRIMARY KEY AUTOINCREMENT,
        "item_id" INTEGER,
        "seller_id" INTEGER,
        "price" REAL,
        "date_added" DATE,
        "time_added" TIME,
        FOREIGN KEY("item_id") REFERENCES "Item"("item_id"),
        FOREIGN KEY("seller_id") REFERENCES "Seller"("seller_id")
    )''')

    cursor.execute('''
    CREATE TABLE "Roles" (
        "role_id" INTEGER PRIMARY KEY AUTOINCREMENT,
        "role_name" TEXT NOT NULL
    )''')

    cursor.execute('''
    CREATE TABLE "Seller" (
        "seller_id" INTEGER PRIMARY KEY AUTOINCREMENT,
        "seller_name" TEXT NOT NULL
    )''')

    cursor.execute('''
    CREATE TABLE "Variation" (
        "variation_id" INTEGER PRIMARY KEY AUTOINCREMENT,
        "variation_name" TEXT NOT NULL
    )''')

    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
