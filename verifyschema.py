import sqlite3
from datetime import date

def get_db_connection():
    # Assuming your database file is named 'clinic.db'
    conn = sqlite3.connect('instance/DMSDB.db')
    conn.row_factory = sqlite3.Row  # This enables column name access
    return conn

def generate_billing(patient_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch patient name
    cursor.execute('SELECT first_name, last_name FROM patients WHERE patient_id = ?', (patient_id,))
    patient = cursor.fetchone()
    if patient:
        patient_name = f"{patient['first_name']} {patient['last_name']}"
    else:
        patient_name = "Unknown"
        print(f"Patient with ID {patient_id} not found.")  # Debugging

    # Fetch diagnoses
    cursor.execute('''
        SELECT tooth_number, condition_code, cost, date_of_diagnosis
        FROM conditions
        WHERE patient_id = ?
    ''', (patient_id,))
    diagnoses = cursor.fetchall()
    print(f"Diagnoses: {diagnoses}")  # Debugging

    # Fetch items used
    cursor.execute('''
        SELECT i.item_name, iu.quantity, iu.date_of_diagnosis, i.cost
        FROM items_used iu
        JOIN Items i ON iu.item_id = i.item_id
        WHERE iu.patient_id = ?
    ''', (patient_id,))
    items_used = cursor.fetchall()
    print(f"Items Used: {items_used}")  # Debugging

    # Calculate total cost
    total_cost = sum(d['cost'] for d in diagnoses if d['cost']) + sum(item['quantity'] * item['cost'] for item in items_used if item['cost'])
    print(f"Total Cost: {total_cost}")  # Debugging

    conn.close()

    # Get current date
    current_date = date.today().strftime("%Y-%m-%d")

    # For simplicity, we'll print the billing information to the console
    print(f"Billing Information for Patient ID: {patient_id}")
    print(f"Patient Name: {patient_name}")
    print(f"Diagnoses: {diagnoses}")
    print(f"Items Used: {items_used}")
    print(f"Total Cost: {total_cost}")
    print(f"Date: {current_date}")

# Replace '1' with the actual patient_id you want to test
generate_billing(1)
