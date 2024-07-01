import sqlite3
import smtplib
import random
import string
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
import json
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
import os

app = Flask(__name__)
app.config['DATABASE'] = 'instance/DMSDB.db'
app.secret_key = 'supersecretkey'

# Email configuration
EMAIL_ADDRESS = 'dentaluserfr@gmail.com'
EMAIL_PASSWORD = 'hvcw gyiy bvyq zwlf'


def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role_id' not in session:
                flash('You need to be logged in to access this page.')
                return redirect(url_for('login'))

            user_role_id = session['role_id']
            # Assuming role_id 1 is admin and role_id 2 is user
            if user_role_id not in roles:
                flash('You do not have permission to access this page.')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)

        return decorated_function

    return decorator

def get_db_connection():
    conn = sqlite3.connect(app.config['DATABASE'], timeout=30)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.row_factory = sqlite3.Row
    return conn

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_email(to_email, subject, body):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)

def generate_captcha():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

def generate_strong_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choices(characters, k=length))
    return password

@app.route('/')
def login():
    return render_template('login.html')


@app.route('/do_login', methods=['POST'])
def do_login():
    login = request.form.get('login')
    password = request.form.get('password')

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ? OR username = ?', (login, login)).fetchone()

    if user:
        if user['is_locked']:
            conn.close()
            return jsonify({'success': False, 'message': 'Account locked due to too many failed login attempts.'})

        if check_password_hash(user['password_hash'], password):
            # Reset failed attempts after successful login
            conn.execute('UPDATE users SET failed_attempts = 0, is_locked = 0 WHERE user_id = ?', (user['user_id'],))
            conn.commit()
            conn.close()

            session['user_id'] = user['user_id']
            session['role_id'] = user['role_id']
            session['first_name'] = user['first_name']
            session['user_email'] = user['email']
            return jsonify({'success': True, 'redirect_url': url_for('dashboard')})
        else:
            failed_attempts = user['failed_attempts'] + 1
            is_locked = 0
            if failed_attempts >= 5:
                is_locked = 1
                conn.execute('UPDATE users SET failed_attempts = ?, is_locked = ?, userstat_id = 6 WHERE user_id = ?',
                             (failed_attempts, is_locked, user['user_id']))
            else:
                conn.execute('UPDATE users SET failed_attempts = ? WHERE user_id = ?',
                             (failed_attempts, user['user_id']))

            conn.commit()
            conn.close()

            if is_locked:
                return jsonify({'success': False, 'message': 'Account locked due to too many failed login attempts.'})
            else:
                return jsonify({'success': False, 'message': 'Invalid credentials. Please try again.'})
    else:
        conn.close()
        return jsonify({'success': False, 'message': 'Invalid credentials. Please try again.'})


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

        if user:
            otp = generate_otp()
            session['otp'] = otp
            session['reset_email'] = email
            session['otp_attempts'] = 0
            session['otp_sent_time'] = datetime.now().isoformat()
            send_email(email, 'Password Reset OTP', f'Your OTP for password reset is {otp}')
            flash('Password reset OTP has been sent to your email.')
            return redirect(url_for('verify_otp'))
        else:
            flash('Email address not found.')

        conn.close()
        return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')



@app.route('/resend_otp', methods=['POST'])
def resend_otp():
    if 'otp_sent_time' in session:
        otp_sent_time_str = session['otp_sent_time']
        otp_sent_time = datetime.fromisoformat(otp_sent_time_str)

        if otp_sent_time and datetime.now().astimezone() - otp_sent_time < timedelta(seconds=session.get('resend_timer', 60)):
            remaining_time = timedelta(seconds=session.get('resend_timer', 60)) - (datetime.now().astimezone() - otp_sent_time)
            return jsonify({'success': False, 'message': f'Please wait {remaining_time.seconds} seconds before resending OTP.'})

    otp = generate_otp()
    session['otp'] = otp
    session['otp_sent_time'] = datetime.now().astimezone().isoformat()
    session['resend_timer'] = session.get('resend_timer', 60) + 60
    send_email(session['reset_email'], 'Password Reset OTP', f'Your OTP for password reset is {otp}')
    return jsonify({'success': True, 'new_timer': session['resend_timer']})


@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        otp = request.form['otp']
        if 'otp' in session:
            if session.get('otp_attempts', 0) >= 3:
                flash('You have reached the maximum number of attempts. Please try again later.')
                return redirect(url_for('forgot_password'))
            if otp == session['otp']:
                flash('OTP verified successfully.')
                session.pop('otp_attempts', None)
                return redirect(url_for('reset_password'))
            else:
                session['otp_attempts'] = session.get('otp_attempts', 0) + 1
                flash('Invalid OTP. Please try again.')
        else:
            flash('OTP session expired. Please request a new OTP.')
        return redirect(url_for('verify_otp'))
    return render_template('verify_otp.html')


def is_password_in_history(user_id, new_password):
    conn = get_db_connection()
    history = conn.execute(
        'SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY changed_at DESC LIMIT 5',
        (user_id,)).fetchall()
    conn.close()

    for record in history:
        if check_password_hash(record['password_hash'], new_password):
            return True
    return False


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match. Please try again.')
            return redirect(url_for('reset_password'))

        hashed_password = generate_password_hash(password)
        email = session.get('reset_email')

        conn = get_db_connection()
        previous_passwords = conn.execute('SELECT password_hash FROM password_history WHERE user_id = (SELECT user_id FROM users WHERE email = ?) ORDER BY changed_at DESC LIMIT 5', (email,)).fetchall()

        for prev_password in previous_passwords:
            if check_password_hash(prev_password['password_hash'], password):
                flash('You cannot use your previous 5 passwords. Please choose a different password.')
                return redirect(url_for('reset_password'))

        # Update the user's password and set their status to active (assuming active status id is 1)
        conn.execute('UPDATE users SET password_hash = ?, userstat_id = 1 WHERE email = ?', (hashed_password, email))
        conn.execute('INSERT INTO password_history (user_id, password_hash) VALUES ((SELECT user_id FROM users WHERE email = ?), ?)', (email, hashed_password))
        conn.commit()
        conn.close()

        session.pop('otp', None)
        session.pop('reset_email', None)
        flash('Your password has been reset successfully. Please login with your new password.')
        return redirect(url_for('login'))
    return render_template('reset_password.html')


@app.route('/dashboard')
def dashboard():
    if 'role_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    appointments = conn.execute('SELECT p.first_name || " " || p.last_name AS patient_name, a.appointment_date, a.start_time, a.end_time FROM appointments a JOIN patients p ON a.patient_id = p.patient_id').fetchall()
    patients = conn.execute('SELECT patient_id, first_name, middle_name, last_name FROM patients').fetchall()
    dentists = conn.execute('SELECT dentist_id, first_name, last_name FROM dentists').fetchall()
    statuses = conn.execute('SELECT status_id, status_name FROM AppointmentStatus').fetchall()
    conn.close()

    first_name = session.get('first_name')
    return render_template('dashboard.html', first_name=first_name, appointments=appointments, patients=patients, dentists=dentists, statuses=statuses)



@app.route('/create_appointment')
def create_appointment():
    conn = get_db_connection()
    patients = conn.execute('SELECT patient_id, first_name, middle_name, last_name FROM patients').fetchall()
    dentists = conn.execute('SELECT dentist_id, first_name, last_name FROM dentists').fetchall()
    statuses = conn.execute('SELECT status_id, status_name FROM AppointmentStatus').fetchall()
    conn.close()
    return render_template('dashboard.html', patients=patients, dentists=dentists, statuses=statuses)


from flask import request, jsonify


@app.route('/submit_appointment', methods=['POST'])
def submit_appointment():
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'No data provided'}), 400

    try:
        patient_id = data['patient_id']
        appointment_date = data['appointment_date']
        start_time = data['start_time']
        end_time = data['end_time']
        appointment_type = data['appointment_type']
        chief_complaints = data['chief_complaints']
        procedures = data['procedures']
        dentist_id = data['dentist_id']
        status_id = data['status_id']
    except KeyError as e:
        return jsonify({'success': False, 'message': f'Missing key: {str(e)}'}), 400

    conn = get_db_connection()

    # Check for conflicts
    conflict = conn.execute('''
        SELECT a.*, 
               p.first_name || " " || p.middle_name || " " || p.last_name AS patient_name,
               d.first_name || " " || d.last_name AS dentist_name
        FROM appointments a
        JOIN patients p ON a.patient_id = p.patient_id
        JOIN dentists d ON a.dentist_id = d.dentist_id
        WHERE a.dentist_id = ? AND a.appointment_date = ? AND (
            (a.start_time <= ? AND a.end_time > ?) OR
            (a.start_time < ? AND a.end_time >= ?) OR
            (a.start_time >= ? AND a.end_time <= ?)
        )
    ''', (dentist_id, appointment_date, start_time, start_time, end_time, end_time, start_time, end_time)).fetchone()

    if conflict:
        conn.close()
        return jsonify({'success': False, 'conflict': dict(conflict)})

    conn.execute('''
        INSERT INTO appointments (patient_id, appointment_date, start_time, end_time, appointment_type, chief_complaints, procedures, dentist_id, status_id) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        patient_id, appointment_date, start_time, end_time, appointment_type, chief_complaints, procedures, dentist_id,
        status_id))

    # Update the patient's next appointment
    conn.execute('UPDATE patients SET next_appointment = ? WHERE patient_id = ?', (appointment_date, patient_id))
    conn.commit()
    conn.close()

    return jsonify({'success': True})


@app.route('/view_appointment')
def view_appointment():
    appointment_id = request.args.get('id')
    conn = get_db_connection()
    appointment = conn.execute('''
        SELECT a.*, 
               p.first_name || " " || p.middle_name || " " || p.last_name AS patient_name,
               d.first_name || " " || d.last_name AS dentist_name
        FROM appointments a
        JOIN patients p ON a.patient_id = p.patient_id
        JOIN dentists d ON a.dentist_id = d.dentist_id
        WHERE a.appointment_id = ?
    ''', (appointment_id,)).fetchone()
    conn.close()

    if appointment:
        return jsonify(dict(appointment))
    return jsonify({'error': 'Appointment not found'}), 404


@app.route('/update_appointment', methods=['POST'])
def update_appointment():
    data = request.get_json()
    appointment_id = data.get('appointment_id')
    appointment_date = data.get('appointment_date')
    start_time = data.get('start_time')
    end_time = data.get('end_time')
    appointment_type = data.get('appointment_type')
    chief_complaints = data.get('chief_complaints')
    procedures = data.get('procedures')
    dentist_id = data.get('dentist_id')
    status_id = data.get('status_id')

    conn = get_db_connection()

    # Check for conflicts with other appointments
    conflict = conn.execute('''
        SELECT * FROM appointments 
        WHERE appointment_date = ? 
        AND dentist_id = ? 
        AND appointment_id != ? 
        AND (
            (start_time < ? AND end_time > ?) OR
            (start_time < ? AND end_time > ?) OR
            (? < start_time AND ? > end_time)
        )
    ''', (appointment_date, dentist_id, appointment_id, start_time, start_time, end_time, end_time, start_time, end_time)).fetchone()

    if conflict:
        conn.close()
        return jsonify({'success': False, 'message': 'Conflict detected with another appointment.'})

    # Update the appointment details
    conn.execute('''
        UPDATE appointments 
        SET appointment_date = ?, start_time = ?, end_time = ?, appointment_type = ?, chief_complaints = ?, procedures = ?, dentist_id = ?, status_id = ?
        WHERE appointment_id = ?
    ''', (appointment_date, start_time, end_time, appointment_type, chief_complaints, procedures, dentist_id, status_id, appointment_id))

    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': 'Appointment updated successfully.'})


@app.route('/cancel_appointment', methods=['POST'])
def cancel_appointment():
    appointment_id = request.form['id']
    conn = get_db_connection()
    conn.execute('DELETE FROM appointments WHERE appointment_id = ?', (appointment_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# Other imports and configurations remain the same

@app.route('/complete_appointment', methods=['POST'])
def complete_appointment():
    appointment_id = request.form['id']
    conn = get_db_connection()
    appointment = conn.execute('SELECT patient_id, appointment_date FROM appointments WHERE appointment_id = ?', (appointment_id,)).fetchone()
    if appointment:
        patient_id = appointment['patient_id']
        appointment_date = appointment['appointment_date']
        conn.execute('UPDATE patients SET last_appointment = ? WHERE patient_id = ?', (appointment_date, patient_id))
        conn.execute('DELETE FROM appointments WHERE appointment_id = ?', (appointment_id,))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    conn.close()
    return jsonify({'success': False, 'message': 'Appointment not found'})

@app.route('/get_appointments')
def get_appointments():
    conn = get_db_connection()
    appointments = conn.execute('''
        SELECT 
            a.appointment_id AS id,
            p.first_name || " " || p.last_name AS title,
            a.appointment_date || "T" || a.start_time AS start,
            a.appointment_date || "T" || a.end_time AS end,
            a.appointment_type,
            a.chief_complaints,
            a.procedures,
            d.first_name || " " || d.last_name AS dentist_name
        FROM appointments a
        JOIN patients p ON a.patient_id = p.patient_id
        JOIN dentists d ON a.dentist_id = d.dentist_id
    ''').fetchall()
    conn.close()

    events = [dict(row) for row in appointments]
    return jsonify(events)


@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query')
    return f"Search results for: {query}"

@app.route('/users')
@role_required([1])  # Only admin can access
def users():
    conn = get_db_connection()
    users = conn.execute('''
        SELECT u.user_id, u.first_name || " " || u.last_name AS name, u.date_created, r.role_name AS role, us.userStatus AS status
        FROM users u
        JOIN roles r ON u.role_id = r.role_id
        JOIN userStatus us ON u.userstat_id = us.userstat_id
    ''').fetchall()
    total_users = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']

    roles = conn.execute('SELECT role_id, role_name FROM roles').fetchall()
    statuses = conn.execute('SELECT userstat_id, userStatus FROM userStatus').fetchall()

    conn.close()

    return render_template('users.html', users=users, total_users=total_users, roles=roles, statuses=statuses)

@app.route('/get_user_details')
def get_user_details():
    user_id = request.args.get('user_id')
    conn = get_db_connection()
    user = conn.execute('''
        SELECT u.user_id, u.first_name, u.last_name, u.username, u.email, u.role_id, u.userstat_id, r.role_name, us.userStatus, u.date_created
        FROM users u
        JOIN roles r ON u.role_id = r.role_id
        JOIN userStatus us ON u.userstat_id = us.userstat_id
        WHERE u.user_id = ?
    ''', (user_id,)).fetchone()
    conn.close()

    if user:
        user_details = {
            'user_id': user['user_id'],
            'first_name': user['first_name'],
            'last_name': user['last_name'],
            'username': user['username'],
            'email': user['email'],
            'role_id': user['role_id'],
            'userstat_id': user['userstat_id'],
            'role_name': user['role_name'],
            'userStatus': user['userStatus'],
            'date_created': user['date_created']
        }
        return jsonify(user_details)
    else:
        return jsonify({'error': 'User not found'}), 404



@app.route('/disable_user', methods=['POST'])
def disable_user():
    data = request.get_json()
    user_id = data['user_id']

    conn = get_db_connection()
    conn.execute('UPDATE users SET userstat_id = ? WHERE user_id = ?', (7, user_id))
    conn.commit()
    conn.close()

    return jsonify({'success': True})



@app.route('/update_user', methods=['POST'])
def update_user():
    data = request.json  # Ensure JSON data is used
    user_id = data.get('user_id')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    username = data.get('username')
    email = data.get('email')
    role_id = data.get('role_id')
    userstat_id = data.get('userstat_id')

    conn = get_db_connection()
    conn.execute('''
        UPDATE users 
        SET first_name = ?, last_name = ?, username = ?, email = ?, role_id = ?, userstat_id = ?
        WHERE user_id = ?
    ''', (first_name, last_name, username, email, role_id, userstat_id, user_id))
    conn.commit()
    conn.close()

    return jsonify({'success': True})



def get_user_status(userstat_id):
    conn = get_db_connection()
    status = conn.execute('SELECT userStatus FROM userStatus WHERE userstat_id = ?', (userstat_id,)).fetchone()
    conn.close()
    return status['userStatus'] if status else 'Unknown'

def get_role_name(role_id):
    conn = get_db_connection()
    role = conn.execute('SELECT role_name FROM roles WHERE role_id = ?', (role_id,)).fetchone()
    conn.close()
    return role['role_name'] if role else 'Unknown'



@app.route('/register_user')
def register_user():
    conn = get_db_connection()
    roles = conn.execute('SELECT role_id, role_name FROM roles').fetchall()
    statuses = conn.execute('SELECT userstat_id, userStatus FROM userStatus').fetchall()
    conn.close()
    return render_template('register_user.html', roles=roles, statuses=statuses)


@app.route('/submit_register_user', methods=['POST'])
def submit_register_user():
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    username = request.form['username']
    email = request.form['email']
    role_id = request.form['role_id']
    userstat_id = request.form['userstat_id']

    # Generate a random strong password
    password = generate_strong_password()
    hashed_password = generate_password_hash(password)

    # Save user to the database
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO users (first_name, last_name, username, email, password_hash, role_id, userstat_id, date_created)
        VALUES (?, ?, ?, ?, ?, ?, ?, DATE('now'))
    ''', (first_name, last_name, username, email, hashed_password, role_id, userstat_id))
    conn.commit()
    conn.close()

    # Send the generated password to the user's email
    send_email(email, 'Your Account Details', f'Your account has been created. Your password is: {password}')

    flash('User registered successfully. The password has been sent to the user\'s email.')
    return redirect(url_for('users'))


@app.route('/patients')
@role_required([1, 2])  # Both admin and user can access
def patients():
    conn = get_db_connection()
    patients = conn.execute('''
        SELECT p.patient_id, p.first_name || ' ' || p.middle_name || ' ' || p.last_name AS name, p.phone AS phone_number, p.address, p.city, p.next_appointment, p.last_appointment, p.register_date, p.email, p.dob AS date_of_birth
        FROM patients p
    ''').fetchall()
    total_patients = conn.execute('SELECT COUNT(*) as count FROM patients').fetchone()['count']
    conn.close()

    return render_template('patients.html', patients=patients, total_patients=total_patients)


@app.route('/overview/<int:patient_id>')
def overview(patient_id):
    conn = get_db_connection()
    patient = conn.execute('SELECT * FROM patients WHERE patient_id = ?', (patient_id,)).fetchone()
    if patient is None:
        flash('Patient not found!', 'danger')
        return redirect(url_for('dashboard'))

    # Calculate age
    birth_date = datetime.strptime(patient['dob'], '%Y-%m-%d')
    today = datetime.today()
    age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))

    patient = dict(patient)
    patient['age'] = age

    appointments = conn.execute('SELECT * FROM appointments WHERE patient_id = ?', (patient_id,)).fetchall()
    treatment = conn.execute('SELECT * FROM treatments WHERE patient_id = ?', (patient_id,)).fetchone()
    examination = conn.execute('SELECT * FROM examinations WHERE patient_id = ?', (patient_id,)).fetchone()
    medical_history = conn.execute('SELECT * FROM medical_history WHERE patient_id = ?', (patient_id,)).fetchone()
    conn.close()

    return render_template('overview.html', 
                           patient=patient, 
                           appointments=appointments, 
                           treatment=treatment or {}, 
                           examination=examination or {}, 
                           medical_history=medical_history or {})

@app.route('/get_patient_details')
def get_patient_details():
    patient_id = request.args.get('patient_id')
    conn = get_db_connection()
    patient_details = conn.execute('''
        SELECT p.patient_id, p.first_name, p.middle_name, p.last_name, p.dob, p.sex, p.address, p.city, p.occupation, p.phone, p.email, p.next_appointment, p.last_appointment, m.medical_history, m.heart_disease_specify, m.blood_pressure, m.allergic_anesthetic_specify, m.extraction_date, m.pregnant_specify, m.hospitalization_specify, m.medicine_specify
        FROM patients p
        LEFT JOIN medical_history m ON p.patient_id = m.patient_id
        WHERE p.patient_id = ?
    ''', (patient_id,)).fetchone()
    conn.close()

    if patient_details:
        patient_details = dict(patient_details)

    return jsonify(patient_details)


@app.route('/add_patient', methods=['POST'])
def add_patient():
    first_name = request.form['first_name']
    middle_name = request.form['middle_name']
    last_name = request.form['last_name']
    dob = request.form['dob']
    phone = request.form['phone']
    email = request.form['email']
    address = request.form['address']
    city = request.form['city']
    next_appointment = request.form['next_appointment']
    last_appointment = request.form['last_appointment']
    emergency_contact_names = request.form.getlist('emergency_contact_name[]')
    emergency_contact_relationships = request.form.getlist('emergency_contact_relationship[]')
    emergency_contact_phones = request.form.getlist('emergency_contact_phone[]')
    medical_conditions = request.form['medical_conditions']
    current_medication = request.form['current_medication']
    employment_status = request.form['employment_status']
    other_employment_detail = request.form.get('other_employment_detail', '')
    occupation = request.form['occupation']

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        INSERT INTO patients 
        (first_name, middle_name, last_name, dob, phone, email, address, city, next_appointment, last_appointment, medical_conditions, current_medication, employment_status, other_employment_detail, occupation, register_date) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATE('now'))
    ''', (first_name, middle_name, last_name, dob, phone, email, address, city, next_appointment, last_appointment,
          medical_conditions, current_medication, employment_status, other_employment_detail, occupation))
    patient_id = cur.lastrowid

    for name, relationship, phone in zip(emergency_contact_names, emergency_contact_relationships,
                                         emergency_contact_phones):
        cur.execute('''
            INSERT INTO emergency_contacts (patient_id, contact_name, relationship, contact_phone) 
            VALUES (?, ?, ?, ?)
        ''', (patient_id, name, relationship, phone))

    conn.commit()
    conn.close()

    flash('Patient added successfully.')
    return redirect(url_for('patients'))

@app.route('/submit_add_patient', methods=['POST'])
def submit_add_patient():
    data = request.json
    first_name = data.get('first_name')
    middle_name = data.get('middle_name')
    last_name = data.get('last_name')
    dob = data.get('dob')
    sex = data.get('sex')
    address = data.get('address')
    city = data.get('city')
    occupation = data.get('occupation')
    phone = data.get('phone')

    try:
        conn = get_db_connection()
        conn.execute('INSERT INTO patients (first_name, middle_name, last_name, dob, sex, address, city, occupation, phone) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                     (first_name, middle_name, last_name, dob, sex, address, city, occupation, phone))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/submit_medical_history', methods=['POST'])
def submit_medical_history():
    try:
        # Retrieve the patient ID and form data for the medical history
        patient_id = request.form['patient_id']
        medical_history = request.form.getlist('medical_history[]')
        heart_disease_specify = request.form.get('heart_disease_specify')
        blood_pressure = request.form.get('blood_pressure')
        allergic_anesthetic_specify = request.form.get('allergic_anesthetic_specify')
        extraction_date = request.form.get('extraction_date')
        pregnant_specify = request.form.get('pregnant_specify')
        hospitalization_specify = request.form.get('hospitalization_specify')
        medicine_specify = request.form.get('medicine_specify')

        # Save the medical history information to the database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO medical_history (patient_id, medical_history, heart_disease_specify, blood_pressure, allergic_anesthetic_specify, extraction_date, pregnant_specify, hospitalization_specify, medicine_specify)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (patient_id, ','.join(medical_history), heart_disease_specify, blood_pressure, allergic_anesthetic_specify, extraction_date, pregnant_specify, hospitalization_specify, medicine_specify))
        conn.commit()
        conn.close()

        # Redirect back to the patients page
        return redirect(url_for('patients'))
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/update_patient', methods=['POST'])
def update_patient():
    data = request.get_json()
    patient_id = data.get('patient_id')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    phone = data.get('phone')
    email = data.get('email')
    address = data.get('address')
    city = data.get('city')
    next_appointment = data.get('next_appointment')
    last_appointment = data.get('last_appointment')
    register_date = data.get('register_date')

    conn = get_db_connection()
    conn.execute('''
        UPDATE patients
        SET first_name = ?, last_name = ?, phone = ?, email = ?, address = ?, city = ?, next_appointment = ?, last_appointment = ?, register_date = ?
        WHERE patient_id = ?
    ''', (first_name, last_name, phone, email, address, city, next_appointment, last_appointment, register_date, patient_id))
    conn.commit()
    conn.close()

    return jsonify({'success': True})

@app.route('/disable_patient', methods=['POST'])
def disable_patient():
    patient_id = request.form['patient_id']
    conn = get_db_connection()
    conn.execute('UPDATE patients SET is_active = 0 WHERE patient_id = ?', (patient_id,))
    conn.commit()
    conn.close()

    return jsonify({'success': True})

@app.route('/patient_records')
def patient_records():
    conn = get_db_connection()
    patient_records = conn.execute('SELECT * FROM patients').fetchall()
    conn.close()
    return render_template('patients.html', records=patient_records)

@app.route('/appointment_records')
def appointment_records():
    conn = get_db_connection()
    appointment_records = conn.execute('SELECT * FROM appointments').fetchall()
    conn.close()
    return render_template('appointment_records.html', records=appointment_records)

@app.route('/records')
@role_required([1])  # Only admin can access
def records():
    return render_template('records.html')

@app.route('/get_records/<record_type>')
def get_records(record_type):
    conn = get_db_connection()
    if record_type == 'appointments':
        data = conn.execute('SELECT * FROM appointments').fetchall()
    elif record_type == 'financial':
        data = conn.execute('SELECT * FROM financial_records').fetchall()
    elif record_type == 'operational':
        data = conn.execute('SELECT * FROM operational_records').fetchall()
    elif record_type == 'communication':
        data = conn.execute('SELECT * FROM communication_records').fetchall()
    else:
        conn.close()
        return jsonify([])

    conn.close()
    
@app.route('/treatments')
def treatments():
    conn = get_db_connection()
    patients = conn.execute('SELECT patient_id, first_name, middle_name, last_name FROM patients').fetchall()
    conn.close()
    return render_template('treatments.html', patients=patients)

@app.route('/intraoral_exam/<int:patient_id>')
def intraoral_exam(patient_id):
    conn = get_db_connection()
    patient = conn.execute('SELECT * FROM patients WHERE patient_id = ?', (patient_id,)).fetchone()
    conn.close()
    if patient is None:
        flash('Patient not found!')
        return redirect(url_for('patients'))
    return render_template('intraoral_exam.html', patient=patient)



@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/inventory')
@role_required([1, 2])  # Both admin and user can access
def inventory():
    conn = get_db_connection()
    inventory_items = conn.execute('SELECT * FROM inventory').fetchall()
    conn.close()
    return render_template('inventory.html', inventory_items=inventory_items)


@app.route('/register_item', methods=['GET', 'POST'])
def register_item():
    if request.method == 'POST':
        name = request.form['name']
        category = request.form['category']
        price = request.form['price']
        stock = request.form['stock']
        variations = request.form['variations']
        seller = request.form['seller']

        conn = get_db_connection()
        conn.execute('''
            INSERT INTO inventory (name, category, price, stock, variations, seller)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (name, category, price, stock, variations, seller))
        conn.commit()
        conn.close()

        flash('Item registered successfully.')
        return redirect(url_for('inventory'))
    return render_template('register_item.html')


@app.route('/item/<int:item_id>')
def view_item(item_id):
    conn = get_db_connection()
    item = conn.execute('SELECT * FROM inventory WHERE id = ?', (item_id,)).fetchone()
    conn.close()
    if item is None:
        flash('Item not found!')
        return redirect(url_for('inventory'))
    return render_template('view_item.html', item=item)


@app.route('/edit_item/<int:item_id>', methods=['GET', 'POST'])
def edit_item(item_id):
    conn = get_db_connection()
    item = conn.execute('SELECT * FROM inventory WHERE id = ?', (item_id,)).fetchone()

    if request.method == 'POST':
        name = request.form['name']
        category = request.form['category']
        price = request.form['price']
        stock = request.form['stock']
        variations = request.form['variations']
        seller = request.form['seller']

        conn.execute('''
            UPDATE inventory
            SET name = ?, category = ?, price = ?, stock = ?, variations = ?, seller = ?
            WHERE id = ?
        ''', (name, category, price, stock, variations, seller, item_id))
        conn.commit()
        conn.close()

        flash('Item updated successfully.')
        return redirect(url_for('inventory'))

    conn.close()
    if item is None:
        flash('Item not found!')
        return redirect(url_for('inventory'))
    return render_template('edit_item.html', item=item)

@app.route('/reports')
@role_required([1, 2])  # Both admin and user can access
def reports():
    return render_template('reports.html')


@app.route('/generate_report/<report_type>', methods=['GET'])
def generate_report(report_type):
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    user_id = session.get('user_id')
    if not user_id:
        return 'User not logged in', 401

    conn = get_db_connection()
    user = conn.execute('SELECT first_name, last_name FROM users WHERE user_id = ?', (user_id,)).fetchone()
    if not user:
        conn.close()
        return 'Invalid user ID', 400
    user_name = f"{user['first_name']} {user['last_name']}"

    if report_type == 'appointments':
        data = conn.execute('''
            SELECT 
                a.appointment_date, 
                (p.last_name || ', ' || p.first_name) as patient_name, 
                a.appointment_type, 
                a.procedures, 
                (d.first_name || ' ' || d.middle_name || ' ' || d.last_name) as dentist_name 
            FROM appointments a
            JOIN patients p ON a.patient_id = p.patient_id
            JOIN dentists d ON a.dentist_id = d.dentist_id
            WHERE a.appointment_date BETWEEN ? AND ?''', (start_date, end_date)).fetchall()
    elif report_type == 'payments':
        data = conn.execute('''
            SELECT 
                p.payment_date AS Date, 
                p.reference_number AS 'Reference Number', 
                (pt.last_name || ', ' || pt.first_name) AS 'Patient Name', 
                p.procedure AS Procedure, 
                p.amount AS Amount
            FROM payments p
            JOIN patients pt ON p.patient_id = pt.patient_id
            WHERE p.payment_date BETWEEN ? AND ?''', (start_date, end_date)).fetchall()
    else:
        conn.close()
        return 'Invalid report type', 400

    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    p.setFont("Helvetica-Bold", 14)
    p.drawCentredString(width / 2.0, height - 50, f"{report_type.capitalize()} Report for Dr. Lorena L. Timola Dental Clinic")

    p.setFont("Helvetica", 12)
    p.drawCentredString(width / 2.0, height - 70, f"Blk 1 Lot 4 Brookside Dr. corner Columbus St Brookside Hills Gate 1, Brgy, Cainta, 1900 Rizal")

    if report_type == 'appointments':
        p.setFont("Helvetica-Bold", 10)
        p.drawString(30, height - 130, "Date")
        p.drawString(100, height - 130, "Patient's Name")
        p.drawString(230, height - 130, "Appointment Type")
        p.drawString(360, height - 130, "Procedures")
        p.drawString(490, height - 130, "Dentist")

        y = height - 150
        p.setFont("Helvetica", 10)
        row_height = 20

        for row in data:
            p.drawString(30, y, row['appointment_date'])
            p.drawString(100, y, row['patient_name'])
            p.drawString(230, y, row['appointment_type'])
            p.drawString(360, y, row['procedures'])
            p.drawString(490, y, row['dentist_name'])
            y -= row_height
            if y < 50:
                p.showPage()
                y = height - 40
                p.setFont("Helvetica-Bold", 10)
                p.drawString(30, y, "Date")
                p.drawString(100, y, "Patient's Name")
                p.drawString(230, y, "Appointment Type")
                p.drawString(360, y, "Procedures")
                p.drawString(490, y, "Dentist")
                y -= row_height
                p.setFont("Helvetica", 10)
    elif report_type == 'payments':
        p.setFont("Helvetica-Bold", 10)
        p.drawString(30, height - 130, "Date")
        p.drawString(100, height - 130, "Reference Number")
        p.drawString(200, height - 130, "Patient's Name")
        p.drawString(330, height - 130, "Procedure")
        p.drawString(460, height - 130, "Amount")

        y = height - 150
        p.setFont("Helvetica", 10)
        row_height = 20

        for row in data:
            p.drawString(30, y, row['Date'])
            p.drawString(100, y, row['Reference Number'])
            p.drawString(200, y, row['Patient Name'])
            p.drawString(330, y, row['Procedure'])
            p.drawString(460, y, str(row['Amount']))
            y -= row_height
            if y < 50:
                p.showPage()
                y = height - 40
                p.setFont("Helvetica-Bold", 10)
                p.drawString(30, y, "Date")
                p.drawString(100, y, "Reference Number")
                p.drawString(200, y, "Patient's Name")
                p.drawString(330, y, "Procedure")
                p.drawString(460, y, "Amount")
                y -= row_height
                p.setFont("Helvetica", 10)

    now = datetime.now()
    p.setFont("Helvetica", 10)
    p.drawString(30, 40, f"Generated by {user_name} on {now.strftime('%Y-%m-%d')} at {now.strftime('%H:%M:%S')}")

    p.showPage()
    p.save()

    buffer.seek(0)
    filename = f"{report_type}_{now.strftime('%Y%m%d_%H%M%S')}.pdf"
    conn.close()
    return send_file(buffer, as_attachment=True, download_name=filename)

@app.route('/get_report/<report_type>')
def get_report(report_type):
    conn = get_db_connection()
    if report_type == 'appointments':
        data = conn.execute('SELECT * FROM appointments').fetchall()
        conn.close()
        return jsonify([dict(row) for row in data])
    elif report_type == 'payments':
        data = conn.execute('SELECT * FROM payments').fetchall()
        conn.close()
        return jsonify([dict(row) for row in data])
    elif report_type == 'patients':
        data = conn.execute('SELECT * FROM patients').fetchall()
        conn.close()
        return jsonify([dict(row) for row in data])
    conn.close()
    return 'Invalid report type', 400

@app.route('/download_report/<report_id>')
def download_report(report_id):
    conn = get_db_connection()
    report = conn.execute('SELECT * FROM reports WHERE report_id = ?', (report_id,)).fetchone()
    conn.close()

    if not report:
        return 'Report not found', 404

    report_details = json.loads(report['details'])
    report_type = report['report_type']

    return render_template('report_result.html', report_type=report_type, data=report_details)

@app.route('/payments')
def payments():
    conn = get_db_connection()
    patients = conn.execute('SELECT patient_id, first_name, middle_name, last_name FROM patients').fetchall()
    conn.close()
    return render_template('payments.html', patients=patients)

@app.route('/process_payment', methods=['POST'])
def process_payment():
    patient = request.form.get('patient')
    payment_method = request.form.get('payment_method')
    amount = request.form.get('amount')
    reference_number = request.form.get('reference_number')
    procedure = request.form.get('procedure')
    payment_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Database connection
    conn = get_db_connection()
    cursor = conn.cursor()

    # Insert payment record into the database
    cursor.execute('''
        INSERT INTO payments (patient_id, payment_method, amount, reference_number, procedure, payment_date)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (patient, payment_method, amount, reference_number, procedure, payment_date))

    conn.commit()
    conn.close()

    return jsonify({'success': True})

@app.route('/generate_receipt')
def generate_receipt():
    patient_id = request.args.get('patient_id')
    payment_method = request.args.get('payment_method')
    amount = request.args.get('amount')
    reference_number = request.args.get('reference_number')
    payment_date = request.args.get('payment_date')

    conn = get_db_connection()
    patient = conn.execute('SELECT * FROM patients WHERE patient_id = ?', (patient_id,)).fetchone()
    conn.close()

    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    p.setFont("Helvetica", 12)
    p.drawString(100, height - 100, f"Receipt for Payment")
    p.drawString(100, height - 120, f"Patient: {patient['first_name']} {patient['middle_name']} {patient['last_name']}")
    p.drawString(100, height - 140, f"Payment Method: {payment_method}")
    p.drawString(100, height - 160, f"Amount: {amount}")
    p.drawString(100, height - 180, f"Reference Number: {reference_number}")
    p.drawString(100, height - 200, f"Payment Date: {payment_date}")
    p.drawString(100, height - 220, f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    p.showPage()
    p.save()
    buffer.seek(0)

    return send_file(buffer, as_attachment=True, download_name='receipt.pdf')

@app.route('/maintenance')
def maintenance():
    return render_template('maintenance.html')

@app.route('/backup_system', methods=['GET'])
def backup_system():
    path = request.args.get('path')
    name = request.args.get('name')
    if not os.path.exists(path):
        return jsonify({"success": False, "error": "Invalid path"}), 400
    
    db_path = os.path.join(path, name)
    try:
        conn = get_db_connection()
        backup_conn = sqlite3.connect(db_path)
        with backup_conn:
            conn.backup(backup_conn, pages=1, progress=None)
        backup_conn.close()
        return jsonify({"success": True, "path": db_path})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/restore_system', methods=['POST'])
def restore_system():
    if 'restore_file' not in request.files:
        return jsonify({"success": False, "error": "No file provided"}), 400

    restore_file = request.files['restore_file']
    restore_path = os.path.join('DMSDB.db')
    
    try:
        restore_file.save(restore_path)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    
@app.route('/help')
def help():
    return render_template('help.html')

@app.route('/about')
def about():
    return render_template('about.html')



if __name__ == '__main__':
    app.run(debug=True)

