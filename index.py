import os
import pymysql
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, PasswordField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
import mercadopago

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Configurar el SDK de Mercado Pago
sdk = mercadopago.SDK("YOUR_ACCESS_TOKEN")

# Configurar PyMySQL
pymysql.install_as_MySQLdb()

# Configuración de base de datos
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'mysql://uyddigykrd5b6y92:R56fundGBbUMxOzH9IoR@bi9craxtek4ln71naubv-mysql.services.clever-cloud.com:3306/bi9craxtek4ln71naubv?charset=utf8mb4&connect_timeout=60&read_timeout=60'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Configuración para el Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'principal'

# Modelo de usuario
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)
    cvu = db.Column(db.Integer, unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Formularios de inicio de sesión y registro
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

# Crear y eliminar las tablas en la base de datos
with app.app_context():
    db.drop_all()
    db.create_all()

# Rutas de la aplicación
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
        password = generate_password_hash(form.password.data)  # Encriptar la contraseña
        cvu = form.cvu.data
        
        # Crear una instancia de usuario
        new_user = User(username=username, email=email, password=password, cvu=cvu)
        
        try:
            # Agregar el nuevo usuario a la base de datos
            db.session.add(new_user)
            db.session.commit()
            
            # Autenticar al usuario después del registro
            login_user(new_user)
            flash('¡Registro exitoso!', 'success')
            return redirect(url_for('home'))  # Redirigir al usuario a la página principal
        except Exception as e:
            db.session.rollback()  # Revertir cualquier cambio si ocurre un error
            flash('Error al registrar el usuario. Por favor, inténtalo de nuevo.', 'danger')
            return redirect(url_for('signup'))  # Redirigir al formulario de registro

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
        
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):  # Verificar la contraseña encriptada
            login_user(user)
            flash('¡Inicio de sesión exitoso!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Email o contraseña incorrectos', 'danger')
            return redirect(url_for('principal'))
    else:
        flash('Fallo en la validación del formulario', 'danger')
        return redirect(url_for('principal'))

@app.route('/logout')
@login_required
def logout():
    """Ruta para cerrar sesión."""
    logout_user()
    flash('Has cerrado sesión', 'info')
    return redirect(url_for('principal'))

@app.route('/process_payment', methods=['POST'])
def process_payment():
    """Ruta para procesar pagos con Mercado Pago."""
    data = request.json

    payment_data = {
        "transaction_amount": float(data['transactionAmount']),
        "token": data['token'],
        "description": data['description'],
        "payment_method_id": data['paymentMethodId'],
        "installments": int(data['installments']),
        "payer": {
            "email": data['payer']['email']
        }
    }

    request_options = mercadopago.config.RequestOptions()
    request_options.custom_headers = {
        'x-idempotency-key': '<SOME_UNIQUE_VALUE>'
    }

    payment_response = sdk.payment().create(payment_data, request_options)
    return jsonify(payment_response["response"])

if __name__ == '__main__':
    app.run(debug=True, port=3500)
