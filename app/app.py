from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import check_password_hash, generate_password_hash
from models import User
from extensions import db
from flask_sqlalchemy import SQLAlchemy
import psycopg2

app = Flask(__name__)
app.config.from_object('config.Config')

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
            return redirect(url_for('welcome'))
        else:
            # Clear previous flash messages
            session.pop('_flashes', None)
            flash('Login failed. Check your username and/or password.', 'error')
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
    session.pop('user_id', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
