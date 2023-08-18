from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt
from flask_login import UserMixin

db = SQLAlchemy()

bcrypt = Bcrypt()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), default='Viewer')
    api_key = db.Column(db.String(120), unique=True, nullable=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.role}')"


class Server(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(120), nullable=False)
    domain = db.Column(db.String(120), nullable=False)
    purpose = db.Column(db.String(120), nullable=False)
    ip_address = db.Column(db.String(20), nullable=False)
    ssh_port = db.Column(db.String(20), nullable=False)
    os = db.Column(db.String(120), nullable=False)
    cores = db.Column(db.String(120), nullable=False)
    ram = db.Column(db.String(120), nullable=False)
    rom = db.Column(db.String(120), nullable=False)
    datacenter = db.Column(db.String(120), nullable=False)
    owner = db.Column(db.String(120), nullable=False)
    comment = db.Column(db.Text, nullable=True)
    superuser_login = db.Column(db.String(120), nullable=False)
    superuser_password = db.Column(db.String(120), nullable=False)  # Encrypted password

    def __repr__(self):
        return f"Server('{self.hostname}', '{self.domain}', '{self.ip_address}')"
    
    def to_dict(self):
        return {
            'id': self.id,
            'hostname': self.hostname,
            'domain': self.domain,
            'purpose': self.purpose,
            'ip_address': self.ip_address,
            'ssh_port': self.ssh_port,
            'os': self.os,
            'cores': self.cores,
            'ram': self.ram,
            'rom': self.rom,
            'datacenter': self.datacenter,
            'owner': self.owner,
            'comment': self.comment }

class AppSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    disable_registration = db.Column(db.Boolean, default=False, nullable=False)
    localization = db.Column(db.String, nullable=False, default='en')
