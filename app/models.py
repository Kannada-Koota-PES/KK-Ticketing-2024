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


class Ticket(db.Model):
    __tablename__ = 'tickets'
    ticket_id = db.Column(db.String(15), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    id_no = db.Column(db.String(30), nullable=False, unique=True)
    phone_no = db.Column(db.String(15))
    email = db.Column(db.String(50), nullable=False)
    is_vip = db.Column(db.Boolean, nullable=False)
    mail_sent = db.Column(db.Boolean, default=False)
    issued_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    issued_at = db.Column(db.DateTime, default=db.func.timezone('UTC', db.func.now()))

    def __init__(self, ticket_id, name, id_no, phone_no, email, is_vip, issued_by):
        self.ticket_id = ticket_id
        self.name = name
        self.id_no = id_no
        self.phone_no = phone_no
        self.email = email
        self.is_vip = is_vip
        self.issued_by = issued_by