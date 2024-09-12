from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'mysql://uyddigykrd5b6y92:R56fundGBbUMxOzH9IoR@bi9craxtek4ln71naubv-mysql.services.clever-cloud.com:3306/bi9craxtek4ln71naubv?charset=utf8mb4&connect_timeout=60&read_timeout=60'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Configuración para el Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'principal'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)
    cvu = db.Column(db.Integer, unique=True, nullable=False)
    password = db.Column(db.String(30), nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class UserForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Length(1, 80), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

class SignUpForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(1, 40)])
    email = EmailField('Email', validators=[DataRequired(), Length(1, 80), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(6, 30)])
    cvu = PasswordField('CVU', validators=[DataRequired(), Length(8, 10)])
    submit = SubmitField('Sign Up')

# Eliminar y recrear el 'user' para no tener q crear otra db
with app.app_context():
    db.drop_all()
    db.create_all() 

@app.route('/')
def principal():
    """Ruta para la página de inicio de sesión."""
    form = UserForm()
    return render_template('LogIn.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Ruta para la página de registro de usuario."""
    form = SignUpForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        cvu = form.cvu.data
        
        # Crear una instancia de usuario
        new_user = User(username=username, email=email, password=password, cvu=cvu)
        
        # Agrega el nuevo usuario
        db.session.add(new_user)
        db.session.commit()
        
        # Autentificación del user
        login_user(new_user)
        flash('Registration successful!', 'success')
        return redirect(url_for('home'))
    
    return render_template('SignUp.html', form=form)

@app.route('/home')
@login_required
def home():
    """Ruta para la página principal después del inicio de sesión."""
    return render_template('Menu.html')

@app.route('/login', methods=['POST'])
def login():
    """Ruta para procesar el inicio de sesión."""
    form = UserForm(request.form)
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        
        user = User.query.filter_by(email=email, password=password).first()
        if user:
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password', 'danger')
            return redirect(url_for('principal'))
    else:
        flash('Form validation failed', 'danger')
        return redirect(url_for('principal'))

if __name__ == '__main__':
    app.run(debug=True, port=3500)
