import logging
import sys
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import check_password_hash, generate_password_hash
from models import User
from extensions import db

# Initialize Flask app
app = Flask(__name__)
app.config.from_object('config.Config')

# Initialize logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)  # Set your desired log level (INFO, DEBUG, etc.)

# StreamHandler sends logs to stdout (captured by Vercel)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)  # Set the handler log level

# Formatter for the log output
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)

# Add handler to the logger if not already present
if not logger.hasHandlers():
    logger.addHandler(console_handler)

# Initialize the db with the app
db.init_app(app)

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        secret = request.form['secret']

        # Clear previous flash messages
        session.pop('_flashes', None)

        if secret != app.config['SECRET_KEY']:
            flash('Secret is incorrect.', 'error')
            logger.warning('Secret is incorrect.')
            return redirect(url_for('add_user'))

        try:
            user = User(username=username, passwd=generate_password_hash(password))
            db.session.add(user)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash('Failed to add user.', 'error')
            logger.error(f'Failed to add user. {e}')
            return redirect(url_for('add_user'))

        flash('User added successfully.', 'success')
        logger.info(f'User {username} added successfully.')
        return redirect(url_for('login'))

    return render_template('add_user.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            user = User.query.filter_by(username=username).first()
        except Exception as e:
            logger.error(f'Failed to query user. {e}')
            flash('Failed to query user.', 'error')
            return redirect(url_for('login'))
        if user and check_password_hash(user.passwd, password):
            if not user.active:
                # Clear previous flash messages
                session.pop('_flashes', None)
                flash('User is not active.', 'error')
                logger.warning(f'User {username} is not active.')
                return redirect(url_for('login'))
            session['user_id'] = user.id
            logger.info(f'User {username} logged in successfully.')
            return redirect(url_for('welcome'))
        else:
            # Clear previous flash messages
            session.pop('_flashes', None)
            flash('Login failed. Check your username and/or password.', 'error')
            logger.warning(f'Login failed for user {username}.')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/welcome')
def welcome():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        return render_template('welcome.html', user=user)
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    logger.info(f'User {session["user_id"]} logged out.')
    session.pop('user_id', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
