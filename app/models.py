from extensions import db
from werkzeug.security import generate_password_hash

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    passwd = db.Column(db.String(250), nullable=False)
    active = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=db.func.timezone('UTC', db.func.now()))

    def __init__(self, username, passwd):
        self.username = username
        self.passwd = passwd
