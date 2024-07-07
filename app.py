import sqlite3
import smtplib
import random
import string
from datetime import datetime, timedelta, timezone
from email.mime.application import MIMEApplication
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from reportlab.lib.units import inch
from werkzeug.security import generate_password_hash, check_password_hash
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
import json
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import os
from random import randint

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

def send_email(to_email, subject, body, attachment=None, attachment_name=None):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    if attachment and attachment_name:
        part = MIMEApplication(attachment.read(), Name=attachment_name)
        part['Content-Disposition'] = f'attachment; filename="{attachment_name}"'
        msg.attach(part)

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

def log_activity(activity):
    user_number = session.get('user_number')  # Assuming you store the user's number in the session
    user_name = session.get('first_name')  # Assuming you store the user's name in the session
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"{user_number} {current_time}: {activity}"
    conn = get_db_connection()
    conn.execute('INSERT INTO user_logs (user_number, user_name, activity) VALUES (?, ?, ?)', (user_number, user_name, log_message))
    conn.commit()
    conn.close()

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
            log_activity(f'Login attempt failed for locked user: {login}')
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
            session['user_number'] = user['user_number']  # Ensure this is also stored in session
            log_activity(f'User {login} logged in successfully')
            return jsonify({'success': True, 'redirect_url': url_for('dashboard')})
        else:
            failed_attempts = user['failed_attempts'] + 1
            is_locked = 0
            if failed_attempts >= 3:
                is_locked = 1
                conn.execute('UPDATE users SET failed_attempts = ?, is_locked = ?, userstat_id = 6 WHERE user_id = ?',
                             (failed_attempts, is_locked, user['user_id']))
            else:
                conn.execute('UPDATE users SET failed_attempts = ? WHERE user_id = ?',
                             (failed_attempts, user['user_id']))

            conn.commit()
            conn.close()

            if is_locked:
                log_activity(f'User {login} account locked due to too many failed login attempts')
                return jsonify({'success': False, 'message': 'Account locked due to too many failed login attempts.'})
            else:
                log_activity(f'Invalid login attempt for user: {login}')
                return jsonify({'success': False, 'message': 'Invalid credentials. Please try again.'})
    else:
        log_activity(f'Invalid login attempt for non-existing user: {login}')
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
            log_activity(f'Password reset OTP sent to {email}')
            flash('Password reset OTP has been sent to your email.')
            return redirect(url_for('verify_otp'))
        else:
            log_activity(f'Password reset requested for non-existing email: {email}')
            flash('Email address not found.')

        conn.close()
        return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')

# Route to resend OTP for password reset
@app.route('/resend_otp', methods=['POST'])
def resend_otp():
    if 'otp_sent_time' in session:
        otp_sent_time_str = session['otp_sent_time']
        otp_sent_time = datetime.fromisoformat(otp_sent_time_str)

        if otp_sent_time and datetime.now(timezone.utc) - otp_sent_time < timedelta(seconds=session.get('resend_timer', 60)):
            remaining_time = timedelta(seconds=session.get('resend_timer', 60)) - (datetime.now(timezone.utc) - otp_sent_time)
            log_activity('Attempt to resend OTP before timer expiration')
            return jsonify({'success': False, 'message': f'Please wait {remaining_time.seconds} seconds before resending OTP.'})

    otp = generate_otp()
    session['otp'] = otp
    session['otp_sent_time'] = datetime.now(timezone.utc).isoformat()
    session['resend_timer'] = session.get('resend_timer', 60) + 60
    send_email(session['reset_email'], 'Password Reset OTP', f'Your OTP for password reset is {otp}')
    log_activity('OTP resent successfully')
    return jsonify({'success': True, 'new_timer': session['resend_timer']})

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        otp = request.form['otp']
        if 'otp' in session:
            if session.get('otp_attempts', 0) >= 3:
                flash('You have reached the maximum number of attempts. Please try again later.')
                log_activity('Maximum OTP attempts reached')
                return redirect(url_for('forgot_password'))
            if otp == session['otp']:
                flash('OTP verified successfully.')
                session.pop('otp_attempts', None)
                log_activity('OTP verified successfully')
                return redirect(url_for('reset_password'))
            else:
                session['otp_attempts'] = session.get('otp_attempts', 0) + 1
                flash('Invalid OTP. Please try again.')
                log_activity('Invalid OTP attempt')
        else:
            flash('OTP session expired. Please request a new OTP.')
            log_activity('OTP session expired')
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
            log_activity('Failed password reset attempt: Passwords do not match')
            return redirect(url_for('reset_password'))

        hashed_password = generate_password_hash(password)
        email = session.get('reset_email')

        conn = get_db_connection()
        previous_passwords = conn.execute('SELECT password_hash FROM password_history WHERE user_id = (SELECT user_id FROM users WHERE email = ?) ORDER BY changed_at DESC LIMIT 5', (email,)).fetchall()

        for prev_password in previous_passwords:
            if check_password_hash(prev_password['password_hash'], password):
                flash('You cannot use your previous 5 passwords. Please choose a different password.')
                log_activity(f'Failed password reset attempt: Password reused for email {email}')
                return redirect(url_for('reset_password'))

        # Update the user's password and set their status to active (assuming active status id is 1)
        conn.execute('UPDATE users SET password_hash = ?, userstat_id = 1 WHERE email = ?', (hashed_password, email))
        conn.execute('INSERT INTO password_history (user_id, password_hash) VALUES ((SELECT user_id FROM users WHERE email = ?), ?)', (email, hashed_password))
        conn.commit()
        conn.close()

        session.pop('otp', None)
        session.pop('reset_email', None)
        flash('Your password has been reset successfully. Please login with your new password.')
        log_activity(f'Password reset successfully for email {email}')
        return redirect(url_for('login'))
    return render_template('reset_password.html')

@app.route('/dashboard')
def dashboard():
    if 'role_id' not in session:
        log_activity('Unauthorized access attempt to dashboard')
        return redirect(url_for('login'))

    conn = get_db_connection()
    appointments = conn.execute('SELECT p.first_name || " " || p.last_name AS patient_name, a.appointment_date, a.start_time, a.end_time FROM appointments a JOIN patients p ON a.patient_id = p.patient_id').fetchall()
    patients = conn.execute('SELECT patient_id, first_name, middle_name, last_name FROM patients').fetchall()
    dentists = conn.execute('SELECT dentist_id, first_name, last_name FROM dentists').fetchall()
    statuses = conn.execute('SELECT status_id, status_name FROM AppointmentStatus').fetchall()
    conn.close()

    first_name = session.get('first_name')
    user_number = session.get('user_number')
    log_activity(f'Dashboard accessed by {first_name}')
    return render_template('dashboard.html', first_name=first_name, appointments=appointments, patients=patients, dentists=dentists, statuses=statuses)

@app.route('/create_appointment', methods=['GET'])
def create_appointment():
    conn = get_db_connection()
    patients = conn.execute('SELECT patient_id, first_name, middle_name, last_name FROM patients').fetchall()
    dentists = conn.execute('SELECT dentist_id, first_name, last_name FROM dentists').fetchall()
    statuses = conn.execute('SELECT status_id, status_name FROM AppointmentStatus').fetchall()
    conn.close()
    user_number = session.get('user_number')
    log_activity(f'{user_number} {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}: Create appointment page accessed')
    return render_template('create_appointment.html', patients=patients, dentists=dentists, statuses=statuses)

@app.route('/view_appointment')
def view_appointment():
    appointment_id = request.args.get('id')
    conn = get_db_connection()
    appointment = conn.execute('''
        SELECT a.*, 
               p.first_name || " " || p.middle_name || " " || p.last_name AS patient_name,
               d.first_name || " " || d.last_name AS dentist_name,
               s.status_name,
               s.status_id
        FROM appointments a
        JOIN patients p ON a.patient_id = p.patient_id
        JOIN dentists d ON a.dentist_id = d.dentist_id
        JOIN AppointmentStatus s ON a.status_id = s.status_id
        WHERE a.appointment_id = ?
    ''', (appointment_id,)).fetchone()
    conn.close()

    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if appointment:
        log_activity(f'{user_number} {current_time}: Viewed appointment {appointment_id}')
        return jsonify(dict(appointment))
    log_activity(f'{user_number} {current_time}: Failed to view appointment {appointment_id} - not found')
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

    selected_date = datetime.strptime(appointment_date, '%Y-%m-%d')
    current_date = datetime.now()

    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if selected_date < current_date:
        log_activity(f'{user_number} {current_time}: Failed to update appointment {appointment_id} - past date selected')
        return jsonify({'success': False, 'message': 'Cannot select a date that has already passed.'})

    conn = get_db_connection()

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
        log_activity(f'{user_number} {current_time}: Failed to update appointment {appointment_id} - conflict detected')
        return jsonify({'success': False, 'message': 'Conflict detected with another appointment.'})

    conn.execute('''
        UPDATE appointments 
        SET appointment_date = ?, start_time = ?, end_time = ?, appointment_type = ?, chief_complaints = ?, procedures = ?, dentist_id = ?, status_id = ?
        WHERE appointment_id = ?
    ''', (appointment_date, start_time, end_time, appointment_type, chief_complaints, procedures, dentist_id, status_id, appointment_id))

    conn.commit()
    conn.close()

    log_activity(f'{user_number} {current_time}: Updated appointment {appointment_id}')
    return jsonify({'success': True, 'message': 'Appointment updated successfully.'})


@app.route('/cancel_appointment', methods=['POST'])
def cancel_appointment():
    appointment_id = request.form['id']
    conn = get_db_connection()
    conn.execute('DELETE FROM appointments WHERE appointment_id = ?', (appointment_id,))
    conn.commit()
    conn.close()

    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_activity(f'{user_number} {current_time}: Cancelled appointment {appointment_id}')

    return jsonify({'success': True})


@app.route('/complete_appointment', methods=['POST'])
def complete_appointment():
    appointment_id = request.form['id']
    conn = get_db_connection()
    appointment = conn.execute('SELECT patient_id, appointment_date FROM appointments WHERE appointment_id = ?',
                               (appointment_id,)).fetchone()
    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if appointment:
        patient_id = appointment['patient_id']
        appointment_date = appointment['appointment_date']
        conn.execute('UPDATE patients SET last_appointment = ? WHERE patient_id = ?', (appointment_date, patient_id))
        conn.execute('DELETE FROM appointments WHERE appointment_id = ?', (appointment_id,))
        conn.commit()
        conn.close()
        log_activity(f'{user_number} {current_time}: Completed appointment {appointment_id}')
        return jsonify({'success': True})

    conn.close()
    log_activity(f'{user_number} {current_time}: Failed to complete appointment {appointment_id} - not found')
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
            s.status_name AS status
        FROM appointments a
        JOIN patients p ON a.patient_id = p.patient_id
        JOIN dentists d ON a.dentist_id = d.dentist_id
        JOIN AppointmentStatus s ON a.status_id = s.status_id
    ''').fetchall()

    conn.close()

    events = [dict(row) for row in appointments]
    log_activity('Retrieved list of appointments')
    return jsonify(events)

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query')
    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_activity(f'{user_number} {current_time}: Search performed with query: {query}')
    return f"Search results for: {query}"

@app.route('/users')
@role_required([1])  # Only admin can access
def users():
    conn = get_db_connection()
    users = conn.execute('''
        SELECT u.user_id, u.first_name || " " || u.last_name AS name, u.date_created, r.role_name AS role, us.userStatus AS status, u.user_number
        FROM users u
        JOIN roles r ON u.role_id = r.role_id
        JOIN userStatus us ON u.userstat_id = us.userstat_id
    ''').fetchall()
    total_users = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']

    roles = conn.execute('SELECT role_id, role_name FROM roles').fetchall()
    statuses = conn.execute('SELECT userstat_id, userStatus FROM userStatus').fetchall()

    conn.close()
    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_activity(f'{user_number} {current_time}: Accessed users page')
    return render_template('users.html', users=users, total_users=total_users, roles=roles, statuses=statuses)

@app.route('/get_user_details')
def get_user_details():
    user_id = request.args.get('user_id')
    conn = get_db_connection()
    user = conn.execute('''
        SELECT u.user_id, u.first_name, u.last_name, u.username, u.email, u.role_id, u.userstat_id, r.role_name, us.userStatus, u.date_created, u.user_number
        FROM users u
        JOIN roles r ON u.role_id = r.role_id
        JOIN userStatus us ON u.userstat_id = us.userstat_id
        WHERE u.user_id = ?
    ''', (user_id,)).fetchone()
    conn.close()

    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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
            'date_created': user['date_created'],
            'user_number': user['user_number']
        }
        log_activity(f'{user_number} {current_time}: Viewed details for user ID {user_id}')
        return jsonify(user_details)
    else:
        log_activity(f'{user_number} {current_time}: Failed to view details for user ID {user_id} - not found')
        return jsonify({'error': 'User not found'}), 404

@app.route('/disable_user', methods=['POST'])
def disable_user():
    data = request.get_json()
    user_id = data['user_id']

    conn = get_db_connection()
    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        conn.execute('UPDATE users SET userstat_id = ? WHERE user_id = ?', (7, user_id))
        conn.commit()
        log_activity(f'{user_number} {current_time}: Disabled user ID {user_id}')
        return jsonify({'success': True})
    except Exception as e:
        log_activity(f'{user_number} {current_time}: Failed to disable user ID {user_id} - {str(e)}')
        return jsonify({'success': False, 'error': str(e)})
    finally:
        conn.close()

@app.route('/update_user', methods=['POST'])
def update_user():
    data = request.json
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

    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_activity(f'{user_number} {current_time}: Updated user ID {user_id}')
    return jsonify({'success': True})

@app.route('/register_user')
def register_user():
    conn = get_db_connection()
    roles = conn.execute('SELECT role_id, role_name FROM roles').fetchall()
    statuses = conn.execute('SELECT userstat_id, userStatus FROM userStatus').fetchall()
    conn.close()
    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_activity(f'{user_number} {current_time}: Accessed user registration page')
    return render_template('register_user.html', roles=roles, statuses=statuses)


def generate_user_number(role_name):
    prefix = 'A-' if role_name == 'Admin' else 'E-'
    random_number = random.randint(100000, 999999)
    return f"{prefix}{random_number}"

@app.route('/submit_register_user', methods=['POST'])
def submit_register_user():
    required_fields = ['first_name', 'last_name', 'username', 'email', 'role_id', 'userstat_id']

    for field in required_fields:
        if field not in request.form:
            flash(f'Missing required field: {field}', 'error')
            return redirect(url_for('users'))

    first_name = request.form['first_name']
    last_name = request.form['last_name']
    username = request.form['username']
    email = request.form['email']
    role_id = request.form['role_id']
    userstat_id = request.form['userstat_id']

    # Generate a random strong password
    password = generate_strong_password()
    hashed_password = generate_password_hash(password)

    # Generate user number based on role
    conn = get_db_connection()
    role = conn.execute('SELECT role_name FROM roles WHERE role_id = ?', (role_id,)).fetchone()

    if role is None:
        flash('Role not found', 'error')
        return redirect(url_for('users'))

    user_number = generate_user_number(role['role_name'])

    # Ensure user_number is unique
    while conn.execute('SELECT 1 FROM users WHERE user_number = ?', (user_number,)).fetchone():
        user_number = generate_user_number(role['role_name'])

    # Save user to the database
    conn.execute('''
        INSERT INTO users (first_name, last_name, username, email, password_hash, role_id, userstat_id, user_number, date_created)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, DATE('now'))
    ''', (first_name, last_name, username, email, hashed_password, role_id, userstat_id, user_number))
    conn.commit()
    conn.close()

    # Send the generated password to the user's email
    send_email(email, 'Your Account Details', f'Your account has been created. Your password is: {password}')

    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    flash('User registered successfully. The password has been sent to the user\'s email.', 'success')
    log_activity(f'{user_number} {current_time}: Registered new user {username} with role ID {role_id}')
    return redirect(url_for('users'))

@app.route('/patients')
@role_required([1, 2])  # Both admin and user can access
def patients():
    conn = get_db_connection()
    patients = conn.execute('''
        SELECT p.patient_id, p.first_name || ' ' || p.middle_name || ' ' || p.last_name AS name, p.mobile_number AS phone_number, p.address, p.city, p.next_appointment, p.last_appointment, p.register_date, p.email, p.dob AS date_of_birth
        FROM patients p
        WHERE p.is_active = 1
    ''').fetchall()
    total_patients = conn.execute('SELECT COUNT(*) as count FROM patients WHERE is_active = 1').fetchone()['count']
    conn.close()

    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_activity(f'{user_number} {current_time}: Accessed patients page')
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

    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_activity(f'{user_number} {current_time}: Viewed overview for patient ID {patient_id}')
    return render_template('overview.html',
                           patient=patient,
                           appointments=appointments,
                           treatment=treatment or {},
                           examination=examination or {},
                           medical_history=medical_history or {})

@app.route('/get_patient_details', methods=['GET'])
def get_patient_details():
    patient_id = request.args.get('patient_id')
    conn = get_db_connection()
    patient = conn.execute('SELECT * FROM patients WHERE patient_id = ?', (patient_id,)).fetchone()
    conn.close()

    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if patient:
        log_activity(f'{user_number} {current_time}: Viewed details for patient ID {patient_id}')
        return jsonify(dict(patient))
    log_activity(f'{user_number} {current_time}: Failed to view details for patient ID {patient_id} - not found')
    return jsonify(error="Patient not found"), 404

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

    for name, relationship, phone in zip(emergency_contact_names, emergency_contact_relationships, emergency_contact_phones):
        cur.execute('''
            INSERT INTO emergency_contacts (patient_id, contact_name, relationship, contact_phone) 
            VALUES (?, ?, ?, ?)
        ''', (patient_id, name, relationship, phone))

    conn.commit()
    conn.close()

    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_activity(f'{user_number} {current_time}: Added new patient {first_name} {last_name}')
    flash('Patient added successfully.')
    return redirect(url_for('patients'))


@app.route('/submit_add_patient', methods=['POST'])
def submit_add_patient():
    data = request.get_json()
    first_name = data['first_name']
    middle_name = data.get('middle_name', '')
    last_name = data['last_name']
    dob = data['dob']
    sex = data['sex']
    address = data['address']
    city = data['city']
    occupation = data.get('occupation', '')
    mobile_number = data['mobile_number']
    email = data['email']

    conn = get_db_connection()
    existing_patient = conn.execute('SELECT * FROM patients WHERE email = ?', (email,)).fetchone()
    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        conn.execute('''
            INSERT INTO patients (first_name, middle_name, last_name, dob, sex, address, city, occupation, mobile_number, email)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (first_name, middle_name, last_name, dob, sex, address, city, occupation, mobile_number, email))
        conn.commit()
        conn.close()
        log_activity(f'{user_number} {current_time}: Submitted new patient {first_name} {last_name}')
        return jsonify(success=True)
    except Exception as e:
        log_activity(f'{user_number} {current_time}: Failed to submit new patient {first_name} {last_name} - {str(e)}')
        return jsonify(success=False, error=str(e))

@app.route('/submit_edit_patient', methods=['POST'])
def submit_edit_patient():
    data = request.get_json()
    patient_id = data['patient_id']
    first_name = data['first_name']
    middle_name = data.get('middle_name', '')
    last_name = data['last_name']
    dob = data['dob']
    sex = data['sex']
    address = data['address']
    city = data['city']
    occupation = data.get('occupation', '')
    mobile_number = data['mobile_number']
    email = data['email']

    conn = get_db_connection()
    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        conn.execute('''
            UPDATE patients
            SET first_name = ?, middle_name = ?, last_name = ?, dob = ?, sex = ?, address = ?, city = ?, occupation = ?, mobile_number = ?, email = ?
            WHERE patient_id = ?
        ''', (first_name, middle_name, last_name, dob, sex, address, city, occupation, mobile_number, email, patient_id))
        conn.commit()
        conn.close()
        log_activity(f'{user_number} {current_time}: Edited patient ID {patient_id}')
        return jsonify(success=True)
    except Exception as e:
        log_activity(f'{user_number} {current_time}: Failed to edit patient ID {patient_id} - {str(e)}')
        return jsonify(success=False, error=str(e))

@app.route('/save_medical_history', methods=['POST'])
def save_medical_history():
    data = request.get_json()
    try:
        conn = get_db_connection()
        conn.execute('''
            INSERT INTO medical_history (
                patient_id, blood_type, blood_pressure, bleeding_time, in_good_health, use_tobacco,
                use_alcohol_drugs, taking_medication, medication, allergies, allergies_details,
                medical_condition, medical_condition_details, serious_illness, serious_illness_details,
                for_woman_only, been_hospitalized, hospitalized_details, high_blood_pressure,
                low_blood_pressure, epilepsy, aids, std, stomach_ulcer, fainting_seizure,
                rapid_weight_loss, radiation_therapy, joint_replacement, heart_surgery,
                heart_attack, thyroid_problem, heart_disease, heart_murmur, hepatitis_liver_disease,
                rheumatic_fever, hay_fever_allergies, respiratory_problems, hepatitis_jaundice,
                tuberculosis, swollen_ankles, kidney_disease, diabetes, chest_pain, stroke,
                cancer_tumors, anemia, angina, asthma, emphysema, bleeding_problems, blood_diseases,
                head_injury, arthritis_rheumatism, other_conditions
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(patient_id) DO UPDATE SET
                blood_type=excluded.blood_type,
                blood_pressure=excluded.blood_pressure,
                bleeding_time=excluded.bleeding_time,
                in_good_health=excluded.in_good_health,
                use_tobacco=excluded.use_tobacco,
                use_alcohol_drugs=excluded.use_alcohol_drugs,
                taking_medication=excluded.taking_medication,
                medication=excluded.medication,
                allergies=excluded.allergies,
                allergies_details=excluded.allergies_details,
                medical_condition=excluded.medical_condition,
                medical_condition_details=excluded.medical_condition_details,
                serious_illness=excluded.serious_illness,
                serious_illness_details=excluded.serious_illness_details,
                for_woman_only=excluded.for_woman_only,
                been_hospitalized=excluded.been_hospitalized,
                hospitalized_details=excluded.hospitalized_details,
                high_blood_pressure=excluded.high_blood_pressure,
                low_blood_pressure=excluded.low_blood_pressure,
                epilepsy=excluded.epilepsy,
                aids=excluded.aids,
                std=excluded.std,
                stomach_ulcer=excluded.stomach_ulcer,
                fainting_seizure=excluded.fainting_seizure,
                rapid_weight_loss=excluded.rapid_weight_loss,
                radiation_therapy=excluded.radiation_therapy,
                joint_replacement=excluded.joint_replacement,
                heart_surgery=excluded.heart_surgery,
                heart_attack=excluded.heart_attack,
                thyroid_problem=excluded.thyroid_problem,
                heart_disease=excluded.heart_disease,
                heart_murmur=excluded.heart_murmur,
                hepatitis_liver_disease=excluded.hepatitis_liver_disease,
                rheumatic_fever=excluded.rheumatic_fever,
                hay_fever_allergies=excluded.hay_fever_allergies,
                respiratory_problems=excluded.respiratory_problems,
                hepatitis_jaundice=excluded.hepatitis_jaundice,
                tuberculosis=excluded.tuberculosis,
                swollen_ankles=excluded.swollen_ankles,
                kidney_disease=excluded.kidney_disease,
                diabetes=excluded.diabetes,
                chest_pain=excluded.chest_pain,
                stroke=excluded.stroke,
                cancer_tumors=excluded.cancer_tumors,
                anemia=excluded.anemia,
                angina=excluded.angina,
                asthma=excluded.asthma,
                emphysema=excluded.emphysema,
                bleeding_problems=excluded.bleeding_problems,
                blood_diseases=excluded.blood_diseases,
                head_injury=excluded.head_injury,
                arthritis_rheumatism=excluded.arthritis_rheumatism,
                other_conditions=excluded.other_conditions
        ''', (
            data.get('patient_id'),
            data.get('blood_type'),
            data.get('blood_pressure'),
            data.get('bleeding_time'),
            data.get('in_good_health', False),
            data.get('use_tobacco', False),
            data.get('use_alcohol_drugs', False),
            data.get('taking_medication', False),
            data.get('medication'),
            data.get('allergies', False),
            data.get('allergies_details'),
            data.get('medical_condition', False),
            data.get('medical_condition_details'),
            data.get('serious_illness', False),
            data.get('serious_illness_details'),
            data.get('for_woman_only'),
            data.get('been_hospitalized', False),
            data.get('hospitalized_details'),
            data.get('high_blood_pressure', False),
            data.get('low_blood_pressure', False),
            data.get('epilepsy', False),
            data.get('aids', False),
            data.get('std', False),
            data.get('stomach_ulcer', False),
            data.get('fainting_seizure', False),
            data.get('rapid_weight_loss', False),
            data.get('radiation_therapy', False),
            data.get('joint_replacement', False),
            data.get('heart_surgery', False),
            data.get('heart_attack', False),
            data.get('thyroid_problem', False),
            data.get('heart_disease', False),
            data.get('heart_murmur', False),
            data.get('hepatitis_liver_disease', False),
            data.get('rheumatic_fever', False),
            data.get('hay_fever_allergies', False),
            data.get('respiratory_problems', False),
            data.get('hepatitis_jaundice', False),
            data.get('tuberculosis', False),
            data.get('swollen_ankles', False),
            data.get('kidney_disease', False),
            data.get('diabetes', False),
            data.get('chest_pain', False),
            data.get('stroke', False),
            data.get('cancer_tumors', False),
            data.get('anemia', False),
            data.get('angina', False),
            data.get('asthma', False),
            data.get('emphysema', False),
            data.get('bleeding_problems', False),
            data.get('blood_diseases', False),
            data.get('head_injury', False),
            data.get('arthritis_rheumatism', False),
            data.get('other_conditions')
        ))
        conn.commit()
        conn.close()

        # Log the activity
        user_number = session.get('user_number')
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_activity(f'{user_number} {current_time}: Saved medical history for patient ID {data.get("patient_id")}')

        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=str(e))

@app.route('/save_diagnosis', methods=['POST'])
def save_diagnosis():
    data = request.get_json()
    patient_id = data.get('patient_id')
    periodontal_screening = ' '.join([key for key, value in data.items() if key in ['G', 'EP', 'MP', 'AP'] and value == 'on'])
    occlusion_class = data.get('occlusion_class')
    appliances = ' '.join([key for key, value in data.items() if key in ['O', 'S', 'OT'] and value == 'on'])
    tmd = ' '.join([key for key, value in data.items() if key in ['C', 'CL', 'T', 'MS'] and value == 'on'])
    xray_taken = ' '.join([key for key, value in data.items() if key in ['P', 'C', 'PT', 'O'] and value == 'on'])
    xray_periapical_tth_no = data.get('xray_periapical_tth_no')
    xray_occlusal = data.get('xray_occlusal')
    xray_others = data.get('xray_others')

    try:
        conn = get_db_connection()
        conn.execute('''
            INSERT INTO intraoral_exams (
                patient_id, periodontal_screening, occlusion_class, appliances, tmd, xray_taken,
                xray_periapical_tth_no, xray_occlusal, xray_others, exam_date
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, DATE('now'))
            ON CONFLICT(patient_id) DO UPDATE SET
                periodontal_screening=excluded.periodontal_screening,
                occlusion_class=excluded.occlusion_class,
                appliances=excluded.appliances,
                tmd=excluded.tmd,
                xray_taken=excluded.xray_taken,
                xray_periapical_tth_no=excluded.xray_periapical_tth_no,
                xray_occlusal=excluded.xray_occlusal,
                xray_others=excluded.xray_others,
                exam_date=DATE('now')
        ''', (
            patient_id, periodontal_screening, occlusion_class, appliances, tmd, xray_taken,
            xray_periapical_tth_no, xray_occlusal, xray_others
        ))
        conn.commit()
        conn.close()

        # Log the activity
        user_number = session.get('user_number')
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_activity(f'{user_number} {current_time}: Saved diagnosis for patient ID {patient_id}')

        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=str(e))



@app.route('/update_patient', methods=['POST'])
def update_patient():
    data = request.get_json()
    patient_id = data['patient_id']
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

    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_activity(f'{user_number} {current_time}: Updated patient ID {patient_id}')
    return jsonify({'success': True})

@app.route('/disable_patient', methods=['POST'])
def disable_patient():
    patient_id = request.form['patient_id']
    conn = get_db_connection()
    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        conn.execute('UPDATE patients SET is_active = 0 WHERE patient_id = ?', (patient_id,))
        conn.commit()
        conn.close()
        log_activity(f'{user_number} {current_time}: Disabled patient ID {patient_id}')
        return jsonify(success=True)
    except Exception as e:
        log_activity(f'{user_number} {current_time}: Failed to disable patient ID {patient_id} - {str(e)}')
        return jsonify(success=False, error=str(e))

@app.route('/treatments')
def treatments():
    conn = get_db_connection()
    patients = conn.execute('SELECT patient_id, first_name, middle_name, last_name FROM patients').fetchall()
    conn.close()
    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_activity(f'{user_number} {current_time}: Accessed treatments page')
    return render_template('treatments.html', patients=patients)


@app.route('/intraoral_exams/<int:patient_id>')
def intraoral_exams(patient_id):
    conn = get_db_connection()
    patient = conn.execute('SELECT * FROM patients WHERE patient_id = ?', (patient_id,)).fetchone()
    if not patient:
        flash('Patient not found!')
        return redirect(url_for('patients'))

    # Calculate age
    birth_date = datetime.strptime(patient['dob'], '%Y-%m-%d')
    today = datetime.today()
    age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))

    patient = dict(patient)
    patient['age'] = age

    intraoral_exams = conn.execute('SELECT * FROM intraoral_exams WHERE patient_id = ?', (patient_id,)).fetchall()
    conn.close()
    log_activity(f'Viewed intraoral exams for patient ID {patient_id}')
    return render_template('intraoral_exam.html', patient=patient, intraoral_exams=intraoral_exams)

@app.route('/logout')
def logout():
    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_activity(f'{user_number} {current_time}: User logged out')
    session.clear()
    return redirect(url_for('login'))

@app.route('/inventory')
@role_required([1, 2])  # Both admin and user can access
def inventory():
    conn = get_db_connection()
    inventory_items = conn.execute('''
        SELECT item_id, name, category, variations, stocked_quantity, seller, price_min, price_max, low_stock_threshold, unit
        FROM inventory
        WHERE is_disabled = 0
    ''').fetchall()
    conn.close()
    return render_template('inventory.html', inventory_items=inventory_items)

@app.route('/submit_add_item', methods=['POST'])
def submit_add_item():
    data = request.get_json()
    name = data['name']
    category = data['category']
    variations = data['variations']
    stocked_quantity = data['stocked_quantity']
    seller = data['seller']
    price_min = data['price_min']
    price_max = data['price_max']
    low_stock_threshold = data['low_stock_threshold']
    unit = data['unit']

    try:
        conn = get_db_connection()
        conn.execute('''
            INSERT INTO inventory (name, category, variations, stocked_quantity, seller, price_min, price_max, low_stock_threshold, unit)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (name, category, variations, stocked_quantity, seller, price_min, price_max, low_stock_threshold, unit))
        conn.commit()
        conn.close()

        # Log the activity
        user_number = session.get('user_number')
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_activity(f'{user_number} {current_time}: Added new item to inventory: {name}')

        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=str(e))

@app.route('/add_stock', methods=['POST'])
def add_stock():
    data = request.get_json()
    item_id = data['item_id']
    additional_stock = data['additional_stock']

    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        conn = get_db_connection()
        conn.execute('UPDATE inventory SET stocked_quantity = stocked_quantity + ? WHERE item_id = ?',
                     (additional_stock, item_id))
        conn.commit()
        conn.close()
        log_activity(f'{user_number} {current_time}: Added stock to item ID {item_id}: {additional_stock} units')
        return jsonify(success=True)
    except Exception as e:
        log_activity(f'{user_number} {current_time}: Failed to add stock to item ID {item_id}: {additional_stock} units - {str(e)}')
        return jsonify(success=False, error=str(e))

@app.route('/deactivate_item', methods=['POST'])
def deactivate_item():
    data = request.get_json()
    item_id = data['item_id']

    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        conn = get_db_connection()
        conn.execute('UPDATE inventory SET is_disabled = 1 WHERE item_id = ?', (item_id,))
        conn.commit()
        conn.close()
        log_activity(f'{user_number} {current_time}: Deactivated item with ID {item_id}')
        return jsonify(success=True)
    except Exception as e:
        log_activity(f'{user_number} {current_time}: Failed to deactivate item with ID {item_id} - {str(e)}')
        return jsonify(success=False, error=str(e))

@app.route('/register_item', methods=['GET', 'POST'])
def register_item():
    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if request.method == 'POST':
        name = request.form['name']
        category = request.form['category']
        variations = request.form['variations']
        stocked_quantity = request.form['stocked_quantity']
        seller = request.form['seller']
        price_min = request.form['price_min']
        price_max = request.form['price_max']
        low_stock_threshold = request.form['low_stock_threshold']

        conn = get_db_connection()
        conn.execute('''
            INSERT INTO inventory (name, category, variations, stocked_quantity, seller, price_min, price_max, low_stock_threshold)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (name, category, variations, stocked_quantity, seller, price_min, price_max, low_stock_threshold))
        conn.commit()
        conn.close()
        log_activity(f'{user_number} {current_time}: Registered new item: {name}')
        flash('Item registered successfully.')
        return redirect(url_for('inventory'))
    return render_template('register_item.html')

@app.route('/item/<int:item_id>')
def view_item(item_id):
    conn = get_db_connection()
    item = conn.execute('SELECT * FROM inventory WHERE item_id = ?', (item_id,)).fetchone()
    conn.close()
    if item is None:
        flash('Item not found!')
        return redirect(url_for('inventory'))

    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_activity(f'{user_number} {current_time}: Viewed item with ID {item_id}')
    return render_template('view_item.html', item=item)

@app.route('/edit_inventory/<int:item_id>', methods=['GET', 'POST'])
@role_required([1])  # Assuming only admin can edit
def edit_inventory(item_id):
    conn = get_db_connection()
    if request.method == 'POST':
        name = request.form['name']
        category = request.form['category']
        variations = request.form['variations']
        stocked_quantity = request.form['stocked_quantity']
        seller = request.form['seller']
        price_min = request.form['price_min']
        price_max = request.form['price_max']
        low_stock_threshold = request.form['low_stock_threshold']
        unit = request.form['unit']

        conn.execute('''
            UPDATE inventory
            SET name = ?, category = ?, variations = ?, stocked_quantity = ?, seller = ?, price_min = ?, price_max = ?, low_stock_threshold = ?, unit = ?
            WHERE item_id = ?
        ''', (name, category, variations, stocked_quantity, seller, price_min, price_max, low_stock_threshold, unit, item_id))
        conn.commit()
        conn.close()

        # Log the activity
        user_number = session.get('user_number')
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_activity(f'{user_number} {current_time}: Edited item with ID {item_id}')

        return redirect(url_for('inventory'))

    item = conn.execute('SELECT * FROM inventory WHERE item_id = ?', (item_id,)).fetchone()
    conn.close()
    return render_template('edit_inventory.html', item=item)

@app.route('/disable_inventory/<int:item_id>')
@role_required([1])  # Assuming only admin can disable
def disable_inventory(item_id):
    conn = get_db_connection()
    item = conn.execute('SELECT is_disabled FROM inventory WHERE item_id = ?', (item_id,)).fetchone()
    new_status = not item['is_disabled']
    conn.execute('UPDATE inventory SET is_disabled = ? WHERE item_id = ?', (new_status, item_id))
    conn.commit()
    conn.close()

    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_activity(f'{user_number} {current_time}: Disabled item with ID {item_id}')
    return redirect(url_for('inventory'))

@app.route('/reports')
@role_required([1, 2])  # Both admin and user can access
def reports():
    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_activity(f'{user_number} {current_time}: Accessed reports page')
    return render_template('reports.html')


@app.route('/generate_report/<report_type>', methods=['GET'])
def generate_report(report_type):
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    # Retrieve logged-in user information from the session
    user_id = session.get('user_id')
    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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
                payment_date, 
                (p.last_name || ', ' || p.first_name) as patient_name, 
                payment_method, 
                amount, 
                reference_number 
            FROM payments py
            JOIN patients p ON py.patient_id = p.patient_id
            WHERE payment_date BETWEEN ? AND ?''', (start_date, end_date)).fetchall()
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
        p.drawString(100, height - 130, "Patient Name")
        p.drawString(230, height - 130, "Payment Type")
        p.drawString(360, height - 130, "Amount")
        p.drawString(490, height - 130, "Reference Number")

        y = height - 150
        p.setFont("Helvetica", 10)
        row_height = 20

        for row in data:
            p.drawString(30, y, row['payment_date'])
            p.drawString(100, y, row['patient_name'])
            p.drawString(230, y, row['payment_method'])
            p.drawString(360, y, str(row['amount']))
            p.drawString(490, y, row['reference_number'])
            y -= row_height
            if y < 50:
                p.showPage()
                y = height - 40
                p.setFont("Helvetica-Bold", 10)
                p.drawString(30, y, "Date")
                p.drawString(100, y, "Patient Name")
                p.drawString(230, y, "Payment Type")
                p.drawString(360, y, "Amount")
                p.drawString(490, y, "Reference Number")
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

    # Log the activity
    log_activity(f'{user_number} {current_time}: Generated {report_type} report from {start_date} to {end_date}')

    return send_file(buffer, as_attachment=True, download_name=filename)

@app.route('/payments')
def payments():
    conn = get_db_connection()
    patients = conn.execute('SELECT patient_id, first_name, middle_name, last_name FROM patients').fetchall()
    conn.close()
    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_activity(f'{user_number} {current_time}: Accessed payments page')
    return render_template('payments.html', patients=patients)

@app.route('/process_payment', methods=['POST'])
def process_payment():
    data = request.json
    patient_id = data['patient']
    payment_method = data['payment_method']
    amount = data['amount']
    services = data['services']
    payment_type = data['payment_type']  # Full or Partial
    reference_number = data.get('reference_number', '')

    # Retrieve logged-in user information from the session
    user_id = session.get('user_id')
    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if not user_id:
        return 'User not logged in', 401

    conn = get_db_connection()
    user = conn.execute('SELECT first_name, last_name FROM users WHERE user_id = ?', (user_id,)).fetchone()
    if not user:
        conn.close()
        return 'Invalid user ID', 400
    user_name = f"{user['first_name']} {user['last_name']}"

    patient = conn.execute('SELECT email, last_name, first_name, middle_name FROM patients WHERE patient_id = ?',
                           (patient_id,)).fetchone()
    if not patient:
        conn.close()
        return 'Invalid patient ID', 400
    patient_full_name = f"{patient['last_name']} {patient['first_name']} {patient['middle_name']}"

    payment_date = datetime.now().strftime('%Y-%m-%d')
    conn.execute(
        'INSERT INTO payments (patient_id, payment_method, amount, payment_date, reference_number, payment_type) VALUES (?, ?, ?, ?, ?, ?)',
        (patient_id, payment_method, amount, payment_date, reference_number, payment_type))

    for service in services:
        conn.execute('INSERT INTO services (patient_id, service_name, amount, payment_date) VALUES (?, ?, ?, ?)',
                     (patient_id, service['name'], service['amount'], payment_date))

    conn.commit()

    # Log the activity
    log_activity(f'{user_number} {current_time}: Processed payment for patient {patient_full_name} ({patient_id}), amount: {amount}, payment method: {payment_method}')

    # Generate the PDF receipt
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    p.setFont("Helvetica-Bold", 14)
    p.drawCentredString(width / 2.0, height - inch, "Service Invoice")

    p.setFont("Helvetica", 12)
    p.drawString(inch, height - 1.5 * inch, f"Date: {payment_date}")
    p.drawString(inch, height - 2 * inch,
                 f"RECEIVED from Dr. Lorena L. Timola Dental Clinic with TIN 912686393 address")
    p.drawString(inch, height - 2.2 * inch,
                 f"at Blk 1 Lot 4 Brookside Dr. Corner Columbus St Brookside Hills Gate 1, Brgy,")
    p.drawString(inch, height - 2.4 * inch,
                 f"Cainta, 1900 Rizal engaged with the business style of Dental Clinic the sum of")
    p.drawString(inch, height - 2.6 * inch, f"{amount} in {payment_type.lower()} payment for {patient_full_name}")

    p.drawString(inch, height - 3 * inch, "IN SETTLEMENT FOR THE FOLLOWING")
    p.drawString(inch, height - 3.2 * inch, "Service        Amount")

    y = height - 3.4 * inch
    for service in services:
        p.drawString(inch, y, f"{service['name']}        {service['amount']}")
        y -= 0.2 * inch

    p.drawString(inch, y - 0.4 * inch, f"FORM OF PAYMENT: {payment_method}")
    p.drawString(inch, y - 0.6 * inch, f"By: {user_name}")

    p.save()
    buffer.seek(0)

    pdf_data = buffer.getvalue()

    # Send the email with the PDF receipt
    send_email(patient['email'], "Payment Receipt", "Please find attached your payment receipt.",
               attachment=BytesIO(pdf_data), attachment_name="Receipt.pdf")

    conn.close()
    return jsonify({'success': True})

@app.route('/maintenance')
def maintenance():
    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_activity(f'{user_number} {current_time}: Accessed maintenance page')
    return render_template('maintenance.html')

@app.route('/backup_system', methods=['GET'])
def backup_system():
    default_path = os.path.join(os.path.expanduser("~"), 'Desktop')
    path = request.args.get('path', default_path)

    if not os.path.exists(path):
        return jsonify({"success": False, "error": "Invalid path"}), 400

    current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_name = f'backup_{current_time}.db'
    backup_path = os.path.join(path, backup_name)

    user_number = session.get('user_number')
    log_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        conn = get_db_connection()
        backup_conn = sqlite3.connect(backup_path)
        with backup_conn:
            conn.backup(backup_conn, pages=1, progress=None)
        backup_conn.close()

        try:
            sqlite3.connect(backup_path).execute('SELECT 1').fetchall()
        except sqlite3.DatabaseError:
            os.remove(backup_path)
            return jsonify({"success": False, "error": "Backup file is not a valid database"}), 500

        # Log the activity
        log_activity(f'{user_number} {log_time}: System backup created at {backup_path}')

        return jsonify({"success": True, "path": backup_path})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/restore_system', methods=['POST'])
def restore_system():
    if 'restore_file' not in request.files:
        return jsonify({"success": False, "error": "No file provided"}), 400

    restore_file = request.files['restore_file']
    restore_path = os.path.join('instance/DMSDB.db')

    user_number = session.get('user_number')
    log_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        restore_file.save(restore_path)

        # Log the activity
        log_activity(f'{user_number} {log_time}: System restored from {restore_file.filename}')

        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/user_log', methods=['GET'])
def user_log():
    try:
        conn = get_db_connection()
        logs = conn.execute('SELECT timestamp, activity FROM user_logs ORDER BY timestamp DESC').fetchall()
        conn.close()
        logs_list = [{'timestamp': log['timestamp'], 'activity': log['activity']} for log in logs]

        user_number = session.get('user_number')
        log_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_activity(f'{user_number} {log_time}: Accessed user log page')

        return jsonify({"success": True, "logs": logs_list})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/help')
def help():
    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_activity(f'{user_number} {current_time}: Accessed help page')
    return render_template('help.html')


@app.route('/add_faq', methods=['GET', 'POST'])
@role_required([1])  # Ensure only admins can access this route
def add_faq():
    if request.method == 'POST':
        question = request.form.get('question')
        answer = request.form.get('answer')

        # Add logic to save the question and answer to the database

        flash('FAQ added successfully!', 'success')
        return redirect(url_for('help'))

    return render_template('add_faq.html')

@app.route('/about')
def about():
    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_activity(f'{user_number} {current_time}: Accessed about page')
    return render_template('about.html')


@app.route('/profile')
def profile():
    user_id = session.get('user_id')
    if not user_id:
        flash('User not logged in', 'error')
        return redirect(url_for('login'))

    conn = get_db_connection()
    user = conn.execute('''
        SELECT u.user_id, u.first_name, u.last_name, u.username, u.email, u.role_id, u.userstat_id, r.role_name, us.userStatus, u.date_created, u.user_number
        FROM users u
        JOIN roles r ON u.role_id = r.role_id
        JOIN userStatus us ON u.userstat_id = us.userstat_id
        WHERE u.user_id = ?
    ''', (user_id,)).fetchone()
    conn.close()

    if user:
        user_details = dict(user)
        session['current_email'] = user['email']  # Save current email in the session

        user_number = session.get('user_number')
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_activity(f'{user_number} {current_time}: Accessed profile page')

        return render_template('profile.html', user=user_details)
    else:
        flash('User not found', 'error')
        return redirect(url_for('dashboard'))

@app.route('/resend_otp_profile', methods=['POST'])
def resend_otp_profile():
    otp = str(randint(100000, 999999))
    session['otp'] = otp
    session['otp_sent_time'] = datetime.now().isoformat()
    send_email(session['current_email'], 'Email Change OTP', f'Your OTP for email change is {otp}')

    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_activity(f'{user_number} {current_time}: Resent OTP for profile email change')

    return jsonify({'success': True})

@app.route('/verify_otp_profile', methods=['POST'])
def verify_otp_profile():
    otp = request.form['otp']
    if 'otp' in session:
        if session.get('otp_attempts', 0) >= 3:
            flash('You have reached the maximum number of attempts. Please try again later.')

            user_number = session.get('user_number')
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_activity(f'{user_number} {current_time}: Reached maximum OTP attempts for profile email change')

            return redirect(url_for('profile'))
        if otp == session['otp']:
            session.pop('otp_attempts', None)
            session['otp_verified'] = True

            user_number = session.get('user_number')
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_activity(f'{user_number} {current_time}: OTP verified for profile email change')

            return jsonify({'success': True, 'next_step': 'new_email'})
        else:
            session['otp_attempts'] = session.get('otp_attempts', 0) + 1
            return jsonify({'success': False, 'message': 'Invalid OTP. Please try again.'})
    else:
        return jsonify({'success': False, 'message': 'OTP session expired. Please request a new OTP.'})

@app.route('/send_new_email_otp_profile', methods=['POST'])
def send_new_email_otp_profile():
    if 'user_id' not in session or not session.get('otp_verified'):
        return redirect(url_for('login'))
    new_email = request.form['new_email']
    otp = str(randint(100000, 999999))
    session['new_email_otp'] = otp
    session['new_email_otp_attempts'] = 0
    session['new_email'] = new_email
    send_email(new_email, 'Your OTP Code', f'Your OTP code is {otp}')

    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_activity(f'{user_number} {current_time}: Sent new email OTP for profile')

    return jsonify({'success': True})

@app.route('/verify_new_email_otp_profile', methods=['POST'])
def verify_new_email_otp_profile():
    new_email_otp = request.form['new_email_otp']
    if 'new_email_otp' in session:
        if session.get('new_email_otp_attempts', 0) >= 3:
            return jsonify({'success': False, 'message': 'You have reached the maximum number of attempts.'})
        if new_email_otp == session['new_email_otp']:
            new_email = session['new_email']
            user_id = session['user_id']
            conn = get_db_connection()
            conn.execute('UPDATE users SET email = ? WHERE user_id = ?', (new_email, user_id))
            conn.commit()
            conn.close()

            session.pop('new_email_otp', None)
            session.pop('new_email', None)
            session.pop('new_email_otp_attempts', None)
            session.pop('otp_verified', None)

            user_number = session.get('user_number')
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_activity(f'{user_number} {current_time}: Verified new email OTP for profile')

            return jsonify({'success': True})
        else:
            session['new_email_otp_attempts'] = session.get('new_email_otp_attempts', 0) + 1
            return jsonify({'success': False, 'message': 'Invalid OTP. Please try again.'})
    else:
        return jsonify({'success': False, 'message': 'OTP session expired. Please request a new OTP.'})

@app.route('/appointment_records')
@role_required([1, 2])  # Both admin and user can access
def appointment_records():
    conn = get_db_connection()
    appointment_records = conn.execute('''
        SELECT 
            a.*, 
            p.first_name || " " || p.middle_name || " " || p.last_name AS patient_name,
            d.first_name || " " || d.last_name AS dentist_name,
            s.status_name
        FROM appointments a
        JOIN patients p ON a.patient_id = p.patient_id
        JOIN dentists d ON a.dentist_id = d.dentist_id
        LEFT JOIN AppointmentStatus s ON a.status_id = s.status_id
    ''').fetchall()

    patients = conn.execute('SELECT patient_id, first_name, middle_name, last_name FROM patients').fetchall()
    dentists = conn.execute('SELECT dentist_id, first_name, last_name FROM dentists').fetchall()
    statuses = conn.execute('SELECT status_id, status_name FROM AppointmentStatus').fetchall()
    conn.close()

    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_activity(f'{user_number} {current_time}: Accessed appointment records page')

    return render_template('appointment_records.html',
                           records=appointment_records,
                           patients=patients,
                           dentists=dentists,
                           statuses=statuses)

@app.route('/submit_appointment', methods=['POST'])
def submit_appointment():
    data = request.json  # Ensure JSON data is used

    # Ensure JSON data is provided
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
        conflict_details = {
            'patient_name': conflict['patient_name'],
            'dentist_name': conflict['dentist_name'],
            'appointment_date': conflict['appointment_date'],
            'start_time': conflict['start_time'],
            'end_time': conflict['end_time']
        }
        return jsonify({'success': False, 'conflict': conflict_details})

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

    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_activity(f'{user_number} {current_time}: Created appointment for patient ID {patient_id} on {appointment_date} from {start_time} to {end_time}')

    return jsonify({'success': True})

@app.route('/treatment_records')
@role_required([1, 2])  # Both admin and user can access
def treatment_records():
    conn = get_db_connection()
    records = conn.execute('''
        SELECT s.payment_date AS treatment_date, 
               p.first_name || ' ' || p.middle_name || ' ' || p.last_name AS patient_name, 
               GROUP_CONCAT(s.service_name, ', ') AS services
        FROM services s
        JOIN patients p ON s.patient_id = p.patient_id
        GROUP BY s.payment_date, p.first_name, p.middle_name, p.last_name
        ORDER BY s.payment_date DESC
    ''').fetchall()
    conn.close()

    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_activity(f'{user_number} {current_time}: Accessed treatment records page')

    return render_template('treatment_records.html', records=records)
@app.route('/change_password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'}), 403

    user_id = session['user_id']
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']

    if new_password != confirm_password:
        return jsonify({'success': False, 'message': 'New password and confirm password do not match'}), 400

    conn = get_db_connection()
    user = conn.execute('SELECT password_hash FROM users WHERE user_id = ?', (user_id,)).fetchone()

    if not user or not check_password_hash(user['password_hash'], current_password):
        conn.close()
        return jsonify({'success': False, 'message': 'Current password is incorrect'}), 400

    previous_passwords = conn.execute(
        'SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY changed_at DESC LIMIT 5',
        (user_id,)).fetchall()

    for prev_password in previous_passwords:
        if check_password_hash(prev_password['password_hash'], new_password):
            conn.close()
            return jsonify({'success': False,
                            'message': 'You cannot use your previous 5 passwords. Please choose a different password.'}), 400

    hashed_new_password = generate_password_hash(new_password)
    conn.execute('UPDATE users SET password_hash = ? WHERE user_id = ?', (hashed_new_password, user_id))
    conn.execute('INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)', (user_id, hashed_new_password))
    conn.commit()
    conn.close()

    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_activity(f'{user_number} {current_time}: Changed password for user ID {user_id}')

    return jsonify({'success': True, 'message': 'Password updated successfully'}), 200

@app.route('/change_email', methods=['POST'])
def change_email():
    password = request.form['password']
    new_email = request.form['new_email']

    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    user = conn.execute('SELECT password_hash FROM users WHERE user_id = ?', (user_id,)).fetchone()

    if not check_password_hash(user['password_hash'], password):
        flash('Password is incorrect. Please try again.')
        conn.close()
        return redirect(url_for('profile'))

    conn.execute('UPDATE users SET email = ? WHERE user_id = ?', (new_email, user_id))
    conn.commit()
    conn.close()

    session['user_email'] = new_email

    # Log the activity
    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_activity(f'{user_number} {current_time}: Changed email to {new_email}.')

    flash('Email changed successfully.')
    return redirect(url_for('profile'))

@app.route('/send_new_email_otp', methods=['POST'])
def send_new_email_otp():
    if 'user_id' not in session or not session.get('otp_verified'):
        return redirect(url_for('login'))
    new_email = request.form['new_email']
    otp = str(randint(100000, 999999))
    expiry = datetime.now() + timedelta(minutes=10)
    user_id = session['user_id']
    conn = get_db_connection()
    conn.execute('UPDATE users SET otp = ?, otp_expiry = ?, otp_attempts = 0 WHERE user_id = ?',
                 (otp, expiry, user_id))
    conn.commit()
    send_email(new_email, 'Your OTP Code', f'Your OTP code is {otp}')
    session['otp_stage'] = 'new_email'
    session['new_email'] = new_email

    # Log the activity
    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_activity(f'{user_number} {current_time}: Requested OTP for email change.')

    return jsonify({'success': True})

@app.route('/verify_otp_for_email_change', methods=['POST'])
def verify_otp_for_email_change():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    otp = request.form['otp']
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE user_id = ?', (user_id,)).fetchone()

    if user['otp_attempts'] >= 3:
        return jsonify({'success': False, 'message': 'Too many failed attempts. Try again later.'})

    if datetime.now() > datetime.strptime(user['otp_expiry'], '%Y-%m-%d %H:%M:%S.%f'):
        return jsonify({'success': False, 'message': 'OTP has expired. Please request a new one.'})

    if user['otp'] == otp:
        conn.execute('UPDATE users SET otp = NULL, otp_expiry = NULL, otp_attempts = 0 WHERE user_id = ?',
                     (user_id,))
        conn.commit()

        # Log the activity
        user_number = session.get('user_number')
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_activity(f'{user_number} {current_time}: Verified OTP for email change.')

        return jsonify({'success': True})
    else:
        conn.execute('UPDATE users SET otp_attempts = otp_attempts + 1 WHERE user_id = ?', (user_id,))
        conn.commit()

        # Log the activity
        user_number = session.get('user_number')
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_activity(f'{user_number} {current_time}: Failed OTP verification for email change.')

        return jsonify({'success': False, 'message': 'Invalid OTP'})

@app.route('/verify_otp_for_password_reset', methods=['GET', 'POST'])
def verify_otp_for_password_reset():
    if request.method == 'POST':
        otp = request.form['otp']
        if 'otp' in session:
            if session.get('otp_attempts', 0) >= 3:
                flash('You have reached the maximum number of attempts. Please try again later.')
                return redirect(url_for('forgot_password'))
            if otp == session['otp']:
                flash('OTP verified successfully.')
                session.pop('otp_attempts', None)

                # Log the activity
                user_number = session.get('user_number')
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log_activity(f'{user_number} {current_time}: Verified OTP for password reset.')

                return redirect(url_for('reset_password'))
            else:
                session['otp_attempts'] = session.get('otp_attempts', 0) + 1
                flash('Invalid OTP. Please try again.')
        else:
            flash('OTP session expired. Please request a new OTP.')
        return redirect(url_for('verify_otp_for_password_reset'))
    return render_template('verify_otp.html')

@app.route('/generate_billing/<int:patient_id>')
@role_required([1, 2])  # Both admin and user can access
def generate_billing(patient_id):
    conn = get_db_connection()

    # Fetch diagnosis details for the patient
    diagnoses = conn.execute('''
        SELECT * FROM diagnosis WHERE patient_id = ?
    ''', (patient_id,)).fetchall()

    # Calculate total cost
    total_cost = sum(d['cost'] for d in diagnoses)

    # Insert billing record
    conn.execute('''
        INSERT INTO billing (patient_id, total_cost, date_of_billing)
        VALUES (?, ?, DATE('now'))
    ''', (patient_id, total_cost))
    conn.commit()

    # Fetch the latest billing record
    billing = conn.execute('''
        SELECT * FROM billing WHERE patient_id = ? ORDER BY date_of_billing DESC LIMIT 1
    ''', (patient_id,)).fetchone()

    # Fetch patient details
    patient = conn.execute('''
        SELECT * FROM patients WHERE patient_id = ?
    ''', (patient_id,)).fetchone()

    conn.close()

    # Log the activity
    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_activity(f'{user_number} {current_time}: Generated billing for patient ID {patient_id} with total cost {total_cost}.')

    return render_template('billing.html', diagnoses=diagnoses, billing=billing, patient=patient)

@app.route('/generate_consent_form/<int:patient_id>')
@role_required([1, 2])  # Both admin and user can access
def generate_consent_form(patient_id):
    conn = get_db_connection()
    patient = conn.execute('SELECT first_name, middle_name, last_name FROM patients WHERE patient_id = ?', (patient_id,)).fetchone()
    conn.close()

    if not patient:
        return 'Patient not found', 404

    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    p.setFont("Helvetica", 12)
    p.drawCentredString(width / 2, height - 50, "Dra. Lorena Timola – Beltran Dental Clinic")
    p.drawCentredString(width / 2, height - 70, "COSMETIC DENTISTRY/ORTHODONTIC")
    p.drawCentredString(width / 2, height - 90, "2561 Brookside Drive Ortigas Ave. Extn. Brookside Hills Subd. Cainta, Rizal")
    p.drawCentredString(width / 2, height - 110, "Tel no: 941-3833 Cell no.: 0917-732-4523")

    p.drawString(30, height - 150, "___________________________________________________________________________________")

    p.setFont("Helvetica-Bold", 16)  # Set the font to bold and size to 16
    p.drawCentredString(width / 2, height - 190, "CONSENT FORM")

    p.setFont("Helvetica", 12)
    p.drawString(30, height - 260, f"Date: {datetime.now().strftime('%Y-%m-%d')}")

    patient_name = f"{patient['last_name']}, {patient['first_name']} {patient['middle_name']}"
    p.drawString(30, height - 370, f"I {patient_name}, hereby consent to the")
    p.drawString(30, height - 390, "performance upon myself of the recommended operations and/or treatments that may")
    p.drawString(30, height - 410, "be considered necessary to restore my oral and dental health. This consent is given")
    p.drawString(30, height - 430, "freely and voluntarily and whatever the result of any intervention or treatment may be, I")
    p.drawString(30, height - 450, "responsibility, be it known, further, that I am willing to pay for all services rendered to")
    p.drawString(30, height - 470, "me/or my family.")

    p.drawString(30, height - 530, "_______________________________________________")
    p.drawString(30, height - 550, "Signature of Patient and/or person responsible for the payment")

    p.showPage()
    p.save()

    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name='Consent_Form.pdf', mimetype='application/pdf')

# Boo's Commit
@app.route('/conditions', methods=['POST'])
def add_condition():
    data = request.json
    required_fields = ['tooth_number', 'condition_code', 'patient_id']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing fields'}), 400

    with sqlite3.connect('instance/DMSDB.db') as conn:
        cur = conn.cursor()
        cur.execute("INSERT INTO conditions (tooth_number, condition_code, patient_id) VALUES (?, ?, ?)",
                    (data['tooth_number'], data['condition_code'], data['patient_id']))
        conn.commit()

    # Log the activity
    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_activity(f'{user_number} {current_time}: Added condition for patient ID {data["patient_id"]}, tooth number {data["tooth_number"]}, condition code {data["condition_code"]}')

    return jsonify({'success': True}), 201


@app.route('/conditions/<int:condition_id>', methods=['DELETE'])
def delete_condition(condition_id):
    with sqlite3.connect('database.db') as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM conditions WHERE condition_id=?", (condition_id,))
        conn.commit()

    # Log the activity
    user_number = session.get('user_number')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_activity(f'{user_number} {current_time}: Deleted condition with ID {condition_id}')

    return jsonify({'success': True}), 200

# Boo's Commit


if __name__ == '__main__':
   app.run(debug=True)
#    app.run(host='192.168.183.72', port=5000, debug=True)

