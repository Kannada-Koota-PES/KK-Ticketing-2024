from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
from werkzeug.security import check_password_hash, generate_password_hash
from models import User, Ticket
from extensions import db
from flask_sqlalchemy import SQLAlchemy
import psycopg2
import random
import string

app = Flask(__name__)
app.config.from_object('config.Config')

# Ensure secure cookies
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

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
            return redirect(url_for('add_user'))

        user = User(username=username, passwd=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()

        flash('User added successfully.', 'success')
        return redirect(url_for('login'))

    return render_template('add_user.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.passwd, password):
            if not user.active:
                # Clear previous flash messages
                session.pop('_flashes', None)
                flash('User is not active.', 'error')
                return redirect(url_for('login'))
            session['user_id'] = user.id
            return redirect(url_for('ticket_entry'))
        else:
            # Clear previous flash messages
            session.pop('_flashes', None)
            flash('Login failed. Check your username and/or password.', 'error')
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

        prev_ticket = Ticket.query.filter_by(id_no=prn).first()
        if prev_ticket:
            # Clear previous flash messages
            session.pop('_flashes', None)
            flash('Ticket already issued.', 'error')
            return redirect(url_for('ticket_entry'))
        
        ticket_id = ''.join(random.choices(string.ascii_letters + string.digits, k=15))
        user_id = session['user_id']
        ticket = Ticket(ticket_id=ticket_id, name=name, id_no=prn, phone_no=phone, email=email, is_vip=True if ticket_type == 'VIP' else False, issued_by=user_id)
        while Ticket.query.filter_by(ticket_id=ticket_id).first():
            ticket_id = ''.join(random.choices(string.ascii_letters + string.digits, k=15))
            ticket.ticket_id = ticket_id
        db.session.add(ticket)
        db.session.commit()

        # Clear previous flash messages
        session.pop('_flashes', None)
        flash('Ticket issued successfully.', 'success')
        return redirect(url_for('ticket_entry'))
    
    if 'user_id' not in session:
        return redirect(url_for('login'))

    response = make_response(render_template('ticket_entry.html'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)