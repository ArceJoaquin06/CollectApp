from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField, SubmitField
from wtforms.validators import DataRequired,Email, Length
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('Conection Uri: mysql://uyddigykrd5b6y92:R56fundGBbUMxOzH9IoR@bi9craxtek4ln71naubv-mysql.services.clever-cloud.com:3306/bi9craxtek4ln71naubv') or 'mysql://uyddigykrd5b6y92:R56fundGBbUMxOzH9IoR@bi9craxtek4ln71naubv-mysql.services.clever-cloud.com:3306/bi9craxtek4ln71naubv'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
#login_manager = LoginManager(app)

class UserForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Length(1, 80), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)
    cvu = db.Column(db.Integer, unique=True, nullable=False)
    password = db.Column(db.String(30), nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)

with app.app_context():
    db.create_all()

"""
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
"""

@app.route('/')
def principal():
    return render_template('Login.html')

@app.route('/SingIn')
def SingIn():
    return render_template('SingIn.html')

@app.route('/home')
def home():
    return render_template('Menu.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    user = User.query.filter_by(username=username, password=password).first()

    if user:
        login_user(user)
        flash('Login successful!', 'success')
        return redirect(url_for('home'))
    else:
        flash('Invalid username or password', 'danger')
        return redirect(url_for('principal'))

if __name__ == '__main__':
    app.run(debug=True, port=3500)