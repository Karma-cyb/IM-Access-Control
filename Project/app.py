#import necessary libraries
from flask import Flask, render_template, flash, redirect, url_for, request
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, PasswordField, BooleanField, SubmitField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
from flask_sqlalchemy import SQLAlchemy as _BaseSQLAlchemy
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.urls import url_parse
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from functools import wraps
from flask import abort
import re
from dotenv import load_dotenv
import os

load_dotenv()  # Load environment variables from .env file

# Database connection setup
dbuser = os.getenv('DB_USER')
dbpass = os.getenv('DB_PASS')
dbhost = os.getenv('DB_HOST')
dbname = os.getenv('DB_NAME')
# Construct the connection string for SQLAlchemy
conn = f"mysql+pymysql://{dbuser}:{dbpass}@{dbhost}/{dbname}"

app = Flask(__name__) #creates flask object

# Flask app configuration
app.config['SECRET_KEY'] = 'SuperSecretKey'
app.config['SQLALCHEMY_DATABASE_URI'] = conn
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Custom SQLAlchemy to fix MySQL "server gone away" issue
class SQLAlchemy(_BaseSQLAlchemy):
    def apply_pool_defaults(self, app, options):
        super(SQLAlchemy, self).apply_pool_defaults(app, options)
        options["pool_pre_ping"] = True

db = SQLAlchemy(app) #connects to sql

# Flask-Login configuration
login = LoginManager(app)
login.login_view = 'login'
login.login_message_category = 'danger'

#access value 
ACCESS = {
    'guest': 0,
    'user': 1,
    'admin': 2
}

# Password strength validation
def password_strength(password):
    if len(password) <= 8:
        return False, "Password must be more than 7 characters."
    elif not re.search("[a-z]", password):
        return False, "Password must contain at least 1 lowercase letter."
    elif not re.search("[A-Z]", password):
        return False, "Password must contain at least 1 uppercase letter."
    elif not re.search("[0-9]", password):
        return False, "Password must contain at least 1 number."
    elif not re.search("[!@#$%^&*():?,.<>]", password):
        return False, "Password must contain at least 1 special character."
    elif re.search("/s", password):
        return False, "Password must not contain any whitespace."
    return True, "Valid password."

# Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    username = db.Column(db.String(30))
    password_hash = db.Column(db.String(128))
    access = db.Column(db.Integer)

    def is_admin(self):
        """Check if the user is an admin."""
        return self.access == ACCESS['admin']

    def is_user(self):
        """Check if the user is an regular user."""
        return self.access == ACCESS['user']

    def allowed(self, access_level):
        """Check if the user has the required access level."""
        return self.access >= access_level

    def set_password(self, password):
        """Hash and store the user's password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verify the user's password."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        """String representation of the User model."""
        return f'<User {self.username}>'

@login.user_loader
def load_user(id):
    """Retrieve a user by ID."""
    return User.query.get(int(id))

# Custom decorator for access level
def requires_access_level(access_level):
    """Decorator to enforce access level restrictions on routes."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('login'))
            if not current_user.allowed(access_level):
                flash('You do not have access to this resource.', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Forms
class LoginForm(FlaskForm): #form for user login
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm): #form for new users refistration
    name = StringField('Name', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')
        
    def validate_username(self, username):
        """Ensure the username is unique."""
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        """Ensure the email is unique."""
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

    def validate_password(self, password):
        """Ensure the password meets strength requirements."""
        is_valid, message = password_strength(password.data)
        if not is_valid:
            raise ValidationError(message)

class ChangePasswordForm(FlaskForm): #form for changing password, only accessible to admins
    """Form for changing user password."""
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')

    def validate_new_password(self, new_password):
        """Ensure the new password meets strength requirements."""
        is_valid, message = password_strength(new_password.data)
        if not is_valid:
            raise ValidationError(message)
        
               
class AccountDetailForm(FlaskForm): # forms for account details
    """Form for updating account details."""
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])

# Routes
@app.route('/')
@app.route('/index')
def index():
    """Homepage route."""
    return render_template('index.html', pageTitle='Flask App Home Page')

@app.route('/about')
def about():
    """About page route."""
    return render_template('about.html', pageTitle='About My Flask App')

#for registering new users
@app.route('/register', methods=['GET', 'POST'])
@requires_access_level(ACCESS['admin'])
def register():
    """Route for user registration."""
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(name=form.name.data, username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


# for logging in
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Route for user login."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid email or password', 'danger')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        flash('You are now logged in', 'success')
        return redirect(next_page)
    return render_template('login.html', form=form)

#for logging out the user
@app.route('/logout')
def logout():
    """Route for logging out the user."""
    logout_user()
    flash('You have successfully logged out.', 'success')
    return redirect(url_for('index'))


#for account details
@app.route('/account/<int:user_id>', methods=['GET', 'POST'])
@login_required
def account(user_id):
    """Route for viewing and editing account details."""
    if user_id != current_user.id:
        abort(403)

    user = User.query.get_or_404(user_id)
    form = AccountDetailForm(obj=user)  # Create the form with the user data pre-filled

    if form.validate_on_submit():
        user.name = form.name.data
        user.email = form.email.data
        user.password = form.password.data  # Make sure to hash the password before saving
        db.session.commit()
        return redirect(url_for('account', user_id=user.id))

    return render_template('account.html', form=form, user_id=user.id)  # Pass 'form' here


@app.route('/dashboard')
@login_required  # Ensures only authenticated users can access
def dashboard():
    """Route for the user dashboard."""
    return render_template('dashboard.html')



@app.route('/account')
@login_required  # Ensures only authenticated users can access
def account_detail():
    """Route for displaying account details."""
    form = AccountDetailForm() # Create an instance of the form
    user_id = current_user.id
    return render_template('account_detail.html', form=form, user_id=user_id)


#control panel only available to the admins
@app.route('/control_panel')
@login_required
@requires_access_level(ACCESS['admin'])  # Restrict control panel to admins
def control_panel():
    """Admin control panel route."""
    users = User.query.all()
    return render_template('control_panel.html', users=users)



@app.route('/users/<int:user_id>', methods=['GET', 'POST'])
@login_required
@requires_access_level(ACCESS['admin'])
def user_detail(user_id):
    """Route for viewing and editing user details."""
    user = User.query.get_or_404(user_id)
    form = AccountDetailForm(obj=user)  # Create an instance of the form
    return render_template('user_detail.html', form=form, user=user)


# for deleting existing users, only available to admins
@app.route('/users/<int:user_id>/delete', methods=['POST'])  # Only allow POST for deletion
@login_required
@requires_access_level(ACCESS['admin'])
def delete_user(user_id):
    """Route for deleting a user."""
    user = User.query.get_or_404(user_id)

    try:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')
    except SQLAlchemyError as e:
        flash(f'Error deleting user: {str(e)}', 'danger')

    return redirect(url_for('control_panel'))  # Redirect to control panel

#for updating user details only availble to admins
@app.route('/users/<int:user_id>/update', methods=['GET', 'POST'])
@login_required
@requires_access_level(ACCESS['admin'])
def update_user(user_id):
    """Route for updating a user's details."""
    user = User.query.get_or_404(user_id)
    form = AccountDetailForm(obj=user)  # Pre-fill form with user data

    if form.validate_on_submit():
        try:
            # Update user attributes
            user.name = form.name.data
            user.access = form.access.data  # Assuming 'access' field in the form
            db.session.commit()
            flash('User updated successfully!', 'success')
            return redirect(url_for('control_panel'))  # Redirect to control panel
        except SQLAlchemyError as e:
            flash(f'Error updating user: {str(e)}', 'danger')
    
    return render_template('user_detail.html', form=form, user=user)

#for changing password only availbe to the admin
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Route for changing the user's"""
    form = ChangePasswordForm()
    if form.validate_on_submit():
        try:
            current_user.password = generate_password_hash(form.new_password.data)  # Directly set the new hashed password
            db.session.commit()
            flash('Password changed successfully!', 'success')
            return redirect(url_for('index'))
        except SQLAlchemyError as e:
            db.session.rollback()
            flash(f'Error changing password: {str(e)}', 'danger') 
    return render_template('change_password.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)
