import logging
import string
import sys
import random
from datetime import timedelta

from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response, jsonify
from werkzeug.security import check_password_hash, generate_password_hash

import pesu_academy_fetch
from models import User, Ticket, TicketLogs
from extensions import db

# Initialize Flask app
app = Flask(__name__)
app.config.from_object('config.Config')

# Set session timeout to 30 minutes
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)

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

# Ensure secure cookies
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

# Initialize the db with the app
db.init_app(app)

# Set session to be permanent (session timeout enabled)
@app.before_request
def make_session_permanent():
    session.permanent = True

# Require login for any routes that need authentication
@app.before_request
def require_login():
    if 'user_id' not in session and request.endpoint not in ['login', 'logout', 'add_user', 'ticket_count']:
        return redirect(url_for('login'))

# Cache control to prevent back button after logout
@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

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

        # Clear previous flash messages
        session.pop('_flashes', None)

        try:
            user = User.query.filter_by(username=username).first()
        except Exception as e:
            logger.error(f'Failed to query user. {e}')
            flash('Failed to query user.', 'error')
            return redirect(url_for('login'))
        if user and check_password_hash(user.passwd, password):
            if not user.active:
                flash('User is not active.', 'error')
                logger.warning(f'User {username} is not active.')
                return redirect(url_for('login'))
            session['user_id'] = user.id
            logger.info(f'User {username} logged in successfully.')
            return redirect(url_for('ticket_entry'))
        else:
            flash('Login failed. Check your username and/or password.', 'error')
            logger.warning(f'Login failed for user {username}.')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/ticket_entry', methods=['GET', 'POST'])
def ticket_entry():
    if request.method == 'POST':
        email = request.form['email']
        phone = request.form['phone']
        prn = request.form['prn']
        name = request.form['name']
        ticket_type = request.form['ticket_type']

        user_id = session['user_id']

        # Clear previous flash messages
        session.pop('_flashes', None)

        # Check if user is active
        user = User.query.filter_by(id=user_id).first()
        if not user.active:
            flash('User is not active.', 'error')
            logger.warning(f'User {user_id} is not active.')
            return redirect(url_for('login'))

        prev_ticket = Ticket.query.filter_by(id_no=prn).first()
        if prev_ticket:
            # Update Email, Phone Number and Ticket Type
            try:
                prev_ticket.email = email
                prev_ticket.phone_no = phone
                prev_ticket.is_vip = True if ticket_type == 'VIP' else False
                prev_ticket.issued_by = user_id
                prev_ticket.mail_sent = False
                db.session.commit()

                # Log the update action
                log_entry = TicketLogs(
                    ticket_id=prev_ticket.ticket_id,
                    action_type='update',
                    email=email,
                    is_vip=prev_ticket.is_vip,
                    issued_by=user_id
                )
                db.session.add(log_entry)
                db.session.commit()

                flash(f'Ticket for {prn} updated successfully.', 'success')
                logger.info(f'Ticket for {prn} updated successfully.')
                return redirect(url_for('ticket_entry'))
            except Exception as e:
                db.session.rollback()
                flash('Failed to update ticket.', 'error')
                logger.error(f'Failed to update ticket. {e}')
                return redirect(url_for('ticket_entry'))
        else:
            ticket_id = ''.join(random.choices(string.ascii_letters + string.digits, k=15))
            ticket = Ticket(ticket_id=ticket_id, name=name, id_no=prn, phone_no=phone, email=email, is_vip=True if ticket_type == 'VIP' else False, issued_by=user_id)
            while Ticket.query.filter_by(ticket_id=ticket_id).first():
                ticket_id = ''.join(random.choices(string.ascii_letters + string.digits, k=15))
                ticket.ticket_id = ticket_id
            try:
                db.session.add(ticket)
                db.session.commit()

                # Log the issue action
                log_entry = TicketLogs(
                    ticket_id=ticket.ticket_id,
                    action_type='issue',
                    email=email,
                    is_vip=ticket.is_vip,
                    issued_by=user_id
                )
                db.session.add(log_entry)
                db.session.commit()

                logger.info(f'Ticket for {prn} issued successfully.')
                flash(f'Ticket for {prn} issued successfully.', 'success')
                return redirect(url_for('ticket_entry'))
            except Exception as e:
                db.session.rollback()
                flash(f'Failed to issue ticket for {prn}.', 'error')
                logger.error(f'Failed to issue ticket. {e}')
                return redirect(url_for('ticket_entry'))
    else:
        if 'user_id' not in session:
            return redirect(url_for('login'))
        response = make_response(render_template('ticket_entry.html'))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response
    
@app.route('/fetch_data', methods=['POST'])
def fetch_data():
    data = request.json
    email = data.get('email')
    phone = data.get('phone')
    prn = data.get('prn')

    # Try fetching data using email, phone, and PRN in that order
    for key, value in [('email', email), ('phone', phone), ('prn', prn)]:
        if value:
            result = pesu_academy_fetch.get_know_your_class_and_section(value)
            if result:
                result['verified_by'] = key
                return jsonify(result)

    return jsonify({'error': 'Data not found'}), 404

@app.route('/ticket_count_PmBtxrTXD94r6BJb8kpP')
def ticket_count():
    try:
        count = Ticket.query.count()
        return jsonify({'count': count})
    except Exception as e:
        logger.error(f'Failed to get ticket count. {e}')
        return jsonify({'error': 'Failed to get ticket count'}), 500
    
@app.route('/check_ticket', methods=['POST'])
def check_ticket():
    data = request.json
    prn = data.get('prn')

    ticket = Ticket.query.filter_by(id_no=prn).first()
    if ticket:
        return jsonify({'ticket': {
            'email': ticket.email,
            'is_vip': ticket.is_vip,
        }}), 200
    else:
        return jsonify({'error': 'Ticket not found'}), 404

@app.route('/logout')
def logout():
    logger.info(f'User {session["user_id"]} logged out.')
    session.clear()  # Clears all session data
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
