import sqlite3
import smtplib
import random
import string
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json

app = Flask(__name__)
app.config['DATABASE'] = 'instance/DMSDB.db'
app.secret_key = 'supersecretkey'

# Email configuration
EMAIL_ADDRESS = 'dentaluserfr@gmail.com'
EMAIL_PASSWORD = 'hvcw gyiy bvyq zwlf'

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


@app.route('/patients')
def patients():
    conn = get_db_connection()
    patients = conn.execute('''
        SELECT 
            patient_id, 
            first_name || " " || middle_name || " " || last_name AS name, 
            phone AS phone_number, 
            address AS city, 
            next_appointment, 
            last_appointment, 
            register_date,
            email
        FROM patients
    ''').fetchall()
    total_patients = conn.execute('SELECT COUNT(*) as count FROM patients').fetchone()['count']
    conn.close()

    return render_template('patients.html', patients=patients, total_patients=total_patients)


@app.route('/view_patient/<int:patient_id>')
def view_patient(patient_id):
    conn = get_db_connection()
    patient = conn.execute('SELECT * FROM patients WHERE patient_id = ?', (patient_id,)).fetchone()
    conn.close()
    return render_template('view_patient.html', patient=patient)


@app.route('/add_patient')
def add_patient():
    return render_template('add_patient.html')


@app.route('/submit_add_patient', methods=['POST'])
def submit_add_patient():
    first_name = request.form['first_name']
    middle_name = request.form['middle_name']
    last_name = request.form['last_name']
    dob = request.form['dob']
    phone_number = request.form['phone']
    email = request.form['email']
    address = request.form['address']
    city = request.form['city']
    next_appointment = request.form['next_appointment']
    last_appointment = request.form['last_appointment']

    conn = get_db_connection()
    conn.execute('''
        INSERT INTO patients (first_name, middle_name, last_name, dob, phone, email, address, city, next_appointment, last_appointment, register_date)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATE('now'))
    ''', (
    first_name, middle_name, last_name, dob, phone_number, email, address, city, next_appointment, last_appointment))
    conn.commit()
    conn.close()

    flash('Patient added successfully')
    return redirect(url_for('patients'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/reports')
def reports():
    return render_template('reports.html')


@app.route('/generate_report', methods=['POST'])
def generate_report():
    report_type = request.form['report_type']
    start_date = request.form['start_date']
    end_date = request.form['end_date']
    user_id = session.get('user_id')  # Assuming you have user sessions

    conn = get_db_connection()

    if report_type == 'appointments':
        data = conn.execute('''
            SELECT * FROM appointments
            WHERE appointment_date BETWEEN ? AND ?
        ''', (start_date, end_date)).fetchall()
        report_details = json.dumps([dict(row) for row in data])

    elif report_type == 'payments':
        data = conn.execute('''
            SELECT * FROM payments
            WHERE payment_date BETWEEN ? AND ?
        ''', (start_date, end_date)).fetchall()
        report_details = json.dumps([dict(row) for row in data])

    elif report_type == 'patients':
        data = conn.execute('''
            SELECT * FROM patients
            WHERE register_date BETWEEN ? AND ?
        ''', (start_date, end_date)).fetchall()
        report_details = json.dumps([dict(row) for row in data])

    else:
        conn.close()
        return 'Invalid report type', 400

    # Insert the report details into the reports table
    conn.execute('''
        INSERT INTO reports (report_type, date_generated, start_date, end_date, generated_by, details)
        VALUES (?, DATE('now'), ?, ?, ?, ?)
    ''', (report_type, start_date, end_date, user_id, report_details))
    conn.commit()
    conn.close()

    return render_template('report_result.html', report_type=report_type, data=json.loads(report_details))

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


if __name__ == '__main__':
    app.run(debug=True)

