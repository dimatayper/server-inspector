from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
import os
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField, IntegerField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from flask_bcrypt import Bcrypt

from db import db, bcrypt, User, Server

import secrets

def generate_api_key():
    return secrets.token_hex(16)

def check_api_key():
    data = request.json
    api_key = data.get('api_key')
    user = User.query.filter_by(api_key=api_key).first()
    if not user:
        return False
    return True


app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'


login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)


db.init_app(app)
bcrypt.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, (int(user_id)))



class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class ServerForm(FlaskForm):
    hostname = StringField('Hostname', validators=[DataRequired()])
    domain = StringField('Domain', validators=[DataRequired()])
    purpose = StringField('Purpose', validators=[DataRequired()])
    ip_address = StringField('IP Address', validators=[DataRequired()])
    ssh_port = IntegerField('SSH Port', validators=[DataRequired()])
    os = StringField('OS', validators=[DataRequired()])
    cores = IntegerField('Cores', validators=[DataRequired()])
    ram = IntegerField('RAM (MB)', validators=[DataRequired()])
    rom = IntegerField('ROM (MB)', validators=[DataRequired()])
    datacenter = StringField('Datacenter', validators=[DataRequired()])
    owner = StringField('Owner', validators=[DataRequired()])
    comment = StringField('Comment', validators=[DataRequired()])
    superuser_login = StringField('Superuser Login', validators=[DataRequired()])
    superuser_password = PasswordField('Superuser Password', validators=[DataRequired()])
    submit = SubmitField('Add Server')


class UpdateServerForm(ServerForm):
    hostname = StringField('Hostname', validators=[DataRequired()])
    domain = StringField('Domain', validators=[DataRequired()])
    ip_address = StringField('IP Address', validators=[DataRequired()])
    submit = SubmitField('Update Server')

class DeleteServerForm(FlaskForm):
    submit = SubmitField('Delete Server')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class UserAdminForm(RegistrationForm):
    roles = SelectField('Role', choices=[('Viewer', 'Viewer'), ('Moderator', 'Moderator'), ('Administrator', 'Administrator')])
    submit = SubmitField('Update User')


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    print(11)
    if current_user.is_authenticated:
        print(12)
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    print(13)
    if form.validate_on_submit():
        print(14)
        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now login.', 'success')
        return redirect(url_for('login'))
    print(15)
    return render_template('register.html', title='Register', form=form)

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', title='Profile')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    servers = Server.query.all()
    return render_template('dashboard.html', title='Dashboard', servers=servers)


@app.route('/server/add', methods=['GET', 'POST'])
@login_required
def add_server():
    if current_user.role not in ['Moderator', 'Administrator']:
        flash('You do not have permissions to add servers.', 'danger')
        return redirect(url_for('dashboard'))
    form = ServerForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.superuser_password.data).decode('utf-8')
        server = Server(
            hostname=form.hostname.data, domain=form.domain.data, purpose=form.purpose.data,
            ip_address=form.ip_address.data, ssh_port=form.ssh_port.data, os=form.os.data,
            cores=form.cores.data, ram=form.ram.data, rom=form.rom.data, datacenter=form.datacenter.data,
            owner=form.owner.data, comment=form.comment.data, superuser_login=form.superuser_login.data,
            superuser_password=hashed_password
        )
        db.session.add(server)
        db.session.commit()
        flash('Server added successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_server.html', title='Add Server', form=form)


@app.route('/server/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_server(id):
    server = db.session.get(Server, id)
    if not server:
        flash('Server not found.', 'danger')
        return redirect(url_for('dashboard'))
    if current_user.role not in ['Moderator', 'Administrator']:
        flash('You do not have permissions to edit servers.', 'danger')
        return redirect(url_for('dashboard'))
    form = UpdateServerForm(obj=server)
    if form.is_submitted():
        server.hostname = form.hostname.data
        server.domain = form.domain.data
        server.ip_address = form.ip_address.data
        server.ssh_port = form.ssh_port.data
        server.os = form.os.data
        server.cores = form.cores.data
        server.ram = form.ram.data
        server.rom = form.rom.data
        server.datacenter = form.datacenter.data
        server.owner = form.owner.data
        server.comment = form.comment.data
        server.superuser_login = form.superuser_login.data
        server.superuser_password = form.superuser_password.data
        db.session.commit()
        flash('Server updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('edit_server.html', form=form, server=server)

@app.route('/server/<int:id>/delete', methods=['GET', 'POST'])
@login_required
def delete_server(id):
    server = db.session.get(Server, id)
    if not server:
        flash('Server not found.', 'danger')
        return redirect(url_for('dashboard'))
    
    if current_user.role != 'Administrator':
        flash('Only Administrators can delete servers.', 'danger')
        return redirect(url_for('dashboard'))
    
    form = DeleteServerForm()
    if form.validate_on_submit():
        db.session.delete(server)
        db.session.commit()
        flash('Server deleted successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('delete_server.html', form=form, server=server)

@app.route('/admin/users')
@login_required
def list_users():
    if current_user.role != 'Administrator':
        flash('Only Administrators can access the admin panel.', 'danger')
        return redirect(url_for('dashboard'))

    users = User.query.all()
    return render_template('list_users.html', users=users)

@app.route('/admin/users/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(id):
    if current_user.role != 'Administrator':
        flash('Only Administrators can edit users.', 'danger')
        return redirect(url_for('dashboard'))

    user = db.session.get(User, id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('dashboard'))

    form = UserAdminForm(obj=user)
    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        user.role = form.roles.data
        if form.password.data:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user.password = hashed_password
        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('list_users'))

    return render_template('edit_user.html', form=form, user=user)

@app.route('/admin/users/<int:id>/delete', methods=['GET', 'POST'])
@login_required
def delete_user(id):
    if current_user.role != 'Administrator':
        flash('Only Administrators can delete users.', 'danger')
        return redirect(url_for('dashboard'))

    user = db.session.get(User, id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')
        return redirect(url_for('list_users'))

    return render_template('delete_user.html', user=user)

@app.route('/generate_api_key', methods=['POST'])
@login_required
def generate_key():
    current_user.api_key = generate_api_key()
    db.session.commit()
    flash('API key has been generated.', 'success')
    return redirect(url_for('profile'))

@app.route('/api/docs', methods=['GET'])
def api_docs():
    return render_template('api_docs.html')

@app.route('/api/servers', methods=['GET'])
def api_list_servers():
    if not check_api_key():
        return jsonify({"error": "Invalid API Key"}), 401

    servers = Server.query.all()
    return jsonify([server.to_dict() for server in servers])

@app.route('/api/servers', methods=['POST'])
def api_add_server():
    if not check_api_key():
        return jsonify({"error": "Invalid API Key"}), 401

    data = request.json
    if "api_key" in data:
        del data["api_key"]
    server = Server(**data)
    db.session.add(server)
    db.session.commit()
    return jsonify(server.to_dict()), 201

@app.route('/api/servers/<int:id>', methods=['PUT'])
def api_update_server(id):
    if not check_api_key():
        return jsonify({"error": "Invalid API Key"}), 401

    server = Server.query.get(id)
    if not server:
        return jsonify({"error": "Server not found"}), 404

    data = request.json
    if "api_key" in data:
        del data["api_key"]
    for key, value in data.items():
        setattr(server, key, value)
    db.session.commit()
    return jsonify(server.to_dict())

@app.route('/api/servers/<int:id>', methods=['DELETE'])
def api_delete_server(id):
    if not check_api_key():
        return jsonify({"error": "Invalid API Key"}), 401

    server = Server.query.get(id)
    if not server:
        return jsonify({"error": "Server not found"}), 404

    db.session.delete(server)
    db.session.commit()
    return jsonify({"message": "Server deleted successfully"})

if __name__ == '__main__':
    app.run(debug=True)
    with app.app_context():
        db.create_all()