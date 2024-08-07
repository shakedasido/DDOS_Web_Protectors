import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
import requests

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'b877d341dcefe7ceeed121c48d9c14b8')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://d_pro_user'
                                                                  ':f63p0Ig8qoZKVic46veOzzPczRM9aQUY@dpg'
                                                                  '-cqou2fij1k6c73d8t2d0-a/d_pro')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['RECAPTCHA_SITE_KEY'] = os.getenv('RECAPTCHA_SITE_KEY', '6LfcbiEqAAAAAKagH8z2LiFu4vICYM81N33DLB4O')
app.config['RECAPTCHA_SECRET_KEY'] = os.getenv('RECAPTCHA_SECRET_KEY', '6LfcbiEqAAAAAPNRMaGNqHU4FVkg_BYUYMfKF2vF')

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)


class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


def verify_recaptcha(recaptcha_response):
    secret_key = app.config['RECAPTCHA_SECRET_KEY']
    payload = {'secret': secret_key, 'response': recaptcha_response}
    response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
    result = response.json()
    return result.get('success', False)


@app.route('/register', methods=['GET', 'POST'])
def register():
    print("Register route accessed")  # Debug print
    form = RegistrationForm()
    if form.validate_on_submit():
        recaptcha_response = request.form['g-recaptcha-response']
        if verify_recaptcha(recaptcha_response):
            existing_user = User.query.filter_by(email=form.email.data).first()
            if existing_user is None:
                new_user = User(email=form.email.data, password=form.password.data)
                db.session.add(new_user)
                db.session.commit()
                flash('Registration successful!', 'success')
                return redirect(url_for('login'))
            else:
                flash('Email already registered. Please use a different email.', 'danger')
        else:
            flash('Invalid reCAPTCHA. Please try again.', 'danger')
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    print("Login route accessed")  # Debug print
    form = LoginForm()
    if form.validate_on_submit():
        recaptcha_response = request.form['g-recaptcha-response']
        if verify_recaptcha(recaptcha_response):
            user = User.query.filter_by(email=form.email.data).first()
            if user and user.password == form.password.data:
                flash('Login successful!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Invalid email or password. Please try again.', 'danger')
        else:
            flash('Invalid reCAPTCHA. Please try again.', 'danger')
    return render_template('login.html', form=form)


@app.route('/')
@app.route('/home')
def home():
    return 'Welcome to the Home Page'


if __name__ == '__main__':
    import os

    port = int(os.environ.get('PORT', 5000))  # Default to port 5000 if PORT not set
    app.run(host='0.0.0.0', port=port, debug=True)
