import sqlite3
import smtplib
import random
import string
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

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
        session['user_role'] = user['role']
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
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        email = session.get('reset_email')

        conn = get_db_connection()
        conn.execute('UPDATE users SET password_hash = ? WHERE email = ?', (hashed_password, email))
        conn.commit()
        conn.close()

        session.pop('otp', None)
        session.pop('reset_email', None)
        flash('Your password has been reset successfully. Please login with your new password.')
        return redirect(url_for('login'))
    return render_template('reset_password.html')

@app.route('/dashboard')
def dashboard():
    if 'user_role' not in session:
        return redirect(url_for('login'))

    if session['user_role'] == 'admin':
        return "Welcome Admin: {}".format(session['user_email'])
    else:
        return "Welcome User: {}".format(session['user_email'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
