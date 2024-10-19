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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        print(len(user.passwd), len(password), check_password_hash(user.passwd, password))
        if user and check_password_hash(user.passwd, password):
            session['user_id'] = user.id
            return redirect(url_for('welcome'))
        else:
            flash('Login failed. Check your username and/or password.')
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
