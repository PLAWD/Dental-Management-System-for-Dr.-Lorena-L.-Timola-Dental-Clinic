from flask_wtf.csrf import generate_csrf
csrf_token = generate_csrf(token_key="your key here")