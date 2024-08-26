from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'

@app.route('/')
def principal():
    return render_template('Login.html')

@app.route('/SingIn')
def SingIn():
    return render_template('SingIn.html')

@app.route('/home')
def home():
    return render_template('Menu.html')

if __name__ == '__main__':
    app.run(debug=True, port=3500)