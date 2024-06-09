import sqlite3
import smtplib
import random
import string
import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.config['DATABASE'] = 'instance/DMSDB.db'
app.secret_key = 'supersecretkey'

# Email configuration
EMAIL_ADDRESS = 'dentaluserfr@gmail.com'
EMAIL_PASSWORD = 'hvcw gyiy bvyq zwlf'
RECAPTCHA_SECRET_KEY = '6LdZh_MpAAAAAFvsPGW7kZPycnli1A0xz5g1-ab9'

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

@app.route('/login', methods=['POST'])
def do_login():
    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()

    if user and check_password_hash(user['password_hash'], password):
        session['user_id'] = user['user_id']
        session['role_id'] = user['role_id']
        session['first_name'] = user['first_name']
        session['user_email'] = user['email']
        return redirect(url_for('dashboard'))
    else:
        return "Invalid credentials. Please try again."

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user:
            otp = generate_otp()
            session['otp'] = otp
            session['reset_email'] = email
            send_email(email, 'Password Reset OTP', f'Your OTP for password reset is {otp}')
            flash('Password reset OTP has been sent to your email.')
            return redirect(url_for('verify_otp'))
        else:
            flash('Email address not found.')

        return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        otp = request.form['otp']
        if 'otp' in session and otp == session['otp']:
            flash('OTP verified successfully.')
            return redirect(url_for('reset_password'))
        else:
            flash('Invalid OTP. Please try again.')
            return redirect(url_for('verify_otp'))
    return render_template('verify_otp.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        captcha = request.form['captcha']
        session_captcha = session.get('captcha')

        if password != confirm_password:
            flash('Passwords do not match. Please try again.')
            return redirect(url_for('reset_password'))

        if captcha != session_captcha:
            flash('Invalid CAPTCHA. Please try again.')
            return redirect(url_for('reset_password'))

        hashed_password = generate_password_hash(password)
        email = session.get('reset_email')

        conn = get_db_connection()
        conn.execute('UPDATE users SET password_hash = ? WHERE email = ?', (hashed_password, email))
        conn.commit()
        conn.close()

        session.pop('otp', None)
        session.pop('reset_email', None)
        session.pop('captcha', None)
        flash('Your password has been reset successfully. Please login with your new password.')
        return redirect(url_for('login'))
    else:
        session['captcha'] = generate_captcha()
    return render_template('reset_password.html', captcha=session['captcha'])

@app.route('/dashboard')
def dashboard():
    if 'role_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    appointments = conn.execute('SELECT p.first_name || " " || p.last_name AS patient_name, a.appointment_date, a.start_time, a.end_time FROM Appointments a JOIN patients p ON a.patient_id = p.patient_id').fetchall()
    conn.close()

    first_name = session.get('first_name')
    return render_template('dashboard.html', first_name=first_name, appointments=appointments)

@app.route('/create_appointment')
def create_appointment():
    conn = get_db_connection()
    patients = conn.execute('SELECT patient_id, first_name, middle_name, last_name FROM patients').fetchall()
    dentists = conn.execute('SELECT dentist_id, first_name, last_name FROM dentists').fetchall()
    conn.close()
    return render_template('create_appointment.html', patients=patients, dentists=dentists)

@app.route('/submit_appointment', methods=['POST'])
def submit_appointment():
    if request.method == 'POST':
        patient_id = request.form['patient']
        appointment_date = request.form['appointmentDate']
        start_time = request.form['startTime']
        end_time = request.form['endTime']
        appointment_type = request.form['appointmentType']
        chief_complaints = request.form['chiefComplaints']
        procedures = request.form['procedures']
        dentist_id = request.form['dentist']

        conn = get_db_connection()
        conn.execute(
            'INSERT INTO appointments (patient_id, appointment_date, start_time, end_time, appointment_type, chief_complaints, procedures, dentist_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            (patient_id, appointment_date, start_time, end_time, appointment_type, chief_complaints, procedures, dentist_id)
        )
        conn.commit()
        conn.close()
        flash('Appointment created successfully')
        return redirect(url_for('dashboard'))

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query')
    return f"Search results for: {query}"

@app.route('/get_appointments')
def get_appointments():
    conn = get_db_connection()
    appointments = conn.execute('''
        SELECT 
            a.appointment_id,
            p.first_name || " " || substr(p.middle_name, 1, 1) || ". " || p.last_name as title,
            a.appointment_date || "T" || a.start_time as start
        FROM appointments a
        JOIN patients p ON a.patient_id = p.patient_id
    ''').fetchall()
    conn.close()

    events = []
    for appointment in appointments:
        events.append({
            'title': appointment['title'],
            'start': appointment['start']
        })

    return jsonify(events)

@app.route('/users')
def users():
    conn = get_db_connection()
    users = conn.execute('''
        SELECT u.user_id, u.first_name || " " || u.last_name AS name, u.date_created, r.role_name AS role, us.userStatus AS status
        FROM users u
        JOIN roles r ON u.role_id = r.role_id
        JOIN userStatus us ON u.userstat_id = us.userstat_id
    ''').fetchall()
    total_users = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
    conn.close()

    return render_template('users.html', users=users, total_users=total_users)

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


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
