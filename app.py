import logging
from flask import Flask, render_template, request, redirect, url_for, session, Markup, flash
from flask_session import Session
from pymongo import MongoClient
from bson import ObjectId
import os
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, validators
from flask import get_flashed_messages
from flask import render_template
from flask_restful import Api, Resource
from flask_babel import Babel, _
from flask_socketio import SocketIO
import re
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.validators import InputRequired, Email, Length, Regexp

# Set up logging
logging.basicConfig(filename='error.log', level=logging.ERROR)

app = Flask(__name__)
socketio = SocketIO(app)
CORS(app)  # Enable CORS for all routes

# Set the secret key before initializing the Session
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Remove the line: Session(app)
SESSION_TYPE = 'filesystem'
app.config.from_object(__name__)
Session(app)

# Babel configuration
babel = Babel(app)
app.config['LANGUAGES'] = ['en', 'es']  # Add more languages as needed

client = MongoClient('mongodb+srv://finalyear:68VBgQHEehmm0mJ4@cluster0.oz1cn45.mongodb.net/')
db = client['student_database']
collection = db['student_collection']

# Use hashed passwords
admin_username = 'sanjay'
admin_password_hash = generate_password_hash('sanjay', method='sha256')

api = Api(app)

class LoginForm(FlaskForm):
    username = StringField(_('Username'), validators=[validators.InputRequired()])
    password = PasswordField(_('Password'), validators=[validators.InputRequired()])
    submit = SubmitField(_('Login'))

class StudentForm(FlaskForm):
    first_name = StringField(_('First Name'), validators=[
        InputRequired(message=_('First Name is required')),
        Regexp(r'^[a-zA-Z ]*$', message=_('Only letters and spaces are allowed'))
    ])
    last_name = StringField(_('Last Name'), validators=[
        InputRequired(message=_('Last Name is required')),
        Regexp(r'^[a-zA-Z ]*$', message=_('Only letters and spaces are allowed'))
    ])
    phone = StringField(_('Phone'), validators=[
        InputRequired(message=_('Phone is required')),
        Regexp(r'^\d{10}$', message=_('Phone must be a 10-digit number'))
    ])
    address = StringField(_('Address'), validators=[
        InputRequired(message=_('Address is required')),
        Length(max=255, message=_('Address cannot exceed 255 characters'))
    ])
    pincode = StringField(_('Pincode'), validators=[
        InputRequired(message=_('Pincode is required')),
        Regexp(r'^\d{6}$', message=_('Pincode must be a 6-digit number'))
    ])
    email = StringField(_('Email'), validators=[
        InputRequired(message=_('Email is required')),
        Email(message=_('Invalid email address'))
    ])
    gender = StringField(_('Gender'), validators=[
        InputRequired(message=_('Gender is required')),
        Regexp(r'^(Male|Female|Other)$', flags=re.IGNORECASE, message=_('Invalid gender'))
    ])
    dob = StringField(_('Date of Birth'), validators=[
        InputRequired(message=_('Date of Birth is required'))
    ])
    submit = SubmitField(_('Submit'))

def is_authenticated():
    return session.get('authenticated', False)

class StudentResource(Resource):
    def get(self, student_id):
        try:
            student = collection.find_one({'_id': ObjectId(student_id)})
            if not student:
                # Log detailed error for debugging
                logging.error(f'Student not found for ID: {student_id}')
                return {'error': _('Student not found')}, 404

            # Escape user-generated content using Markup to prevent XSS
            student['first_name'] = Markup(student['first_name'])
            student['last_name'] = Markup(student['last_name'])
            student['phone'] = Markup(student['phone'])
            student['address'] = Markup(student['address'])
            student['pincode'] = Markup(student['pincode'])
            student['email'] = Markup(student['email'])
            student['gender'] = Markup(student['gender'])
            student['date_of_birth'] = Markup(student['date_of_birth'])

            return {'student': student}, 200

        except Exception as e:
            # Log detailed error for debugging
            logging.error(f'Error in StudentResource GET: {str(e)}')
            return {'error': _('Internal Server Error')}, 500

class StudentListResource(Resource):
    def get(self):
        try:
            student_data = list(collection.find())
            students = []

            for student in student_data:
                # Escape user-generated content using Markup to prevent XSS
                student['first_name'] = Markup(student['first_name'])
                student['last_name'] = Markup(student['last_name'])
                student['phone'] = Markup(student['phone'])
                student['address'] = Markup(student['address'])
                student['pincode'] = Markup(student['pincode'])
                student['email'] = Markup(student['email'])
                student['gender'] = Markup(student['gender'])
                student['date_of_birth'] = Markup(student['date_of_birth'])
                students.append(student)

            return {'students': students}, 200

        except Exception as e:
            # Log detailed error for debugging
            logging.error(f'Error in StudentListResource GET: {str(e)}')
            return {'error': _('Internal Server Error')}, 500

api.add_resource(StudentResource, '/students/<student_id>')
api.add_resource(StudentListResource, '/students')


def is_authenticated():
    return session.get('authenticated', False) == True


# Custom error handling middleware
@app.errorhandler(404)
def page_not_found(error):
    # Log detailed error for debugging
    logging.error(f'Error 404 - Page not found: {str(error)}')
    return render_template('error.html', error_message=_('Page not found'), status_code=404), 404

# Define a custom error handler for 500 Internal Server Error
@app.errorhandler(500)
def internal_server_error(error):
    # Log detailed error for debugging
    logging.error(f'Error 500 - Internal Server Error: {str(error)}')
    return render_template('error.html', error_message=_('Internal Server Error'), status_code=500), 500

# Define a custom error handler for other exceptions
@app.errorhandler(Exception)
def handle_exception(error):
    # Log detailed error for debugging
    logging.error(f'Unhandled Exception: {str(error)}')
    return render_template('error.html', error_message=_('Something went wrong!'), status_code=500), 500

@app.route('/')
def index():
    form = StudentForm()  # Create an instance of the StudentForm
    # Pass flash messages to the template context
    messages = get_flashed_messages()
    return render_template('index.html', form=form, messages=messages)

@app.route('/submit', methods=['POST'])
def submit():
    form = StudentForm(request.form)

    if form.validate():
        first_name = form.first_name.data
        last_name = form.last_name.data
        phone = form.phone.data
        address = form.address.data
        pincode = form.pincode.data
        email = form.email.data
        gender = form.gender.data
        dob = form.dob.data

        student_data = {
            'first_name': first_name,
            'last_name': last_name,
            'phone': phone,
            'address': address,
            'pincode': pincode,
            'email': email,
            'gender': gender,
            'date_of_birth': dob
        }

        try:
            collection.insert_one(student_data)
            flash(_('Thank you for your submission!'), 'success')
        except Exception as e:
            # Log detailed error for debugging
            logging.error(f'Error in submit route: {str(e)}')
            flash(_('An error occurred. Please try again later.'), 'danger')

        return redirect(url_for('index'))
    else:
        flash(_('Invalid input. Please check your entries.'), 'danger')
        return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def admin_login():
    form = LoginForm()  # Create an instance of the LoginForm
    if request.method == 'POST' and form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        if username == admin_username and check_password_hash(admin_password_hash, password):
            session['authenticated'] = True
            flash(_('Login successful!'), 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash(_('Invalid Username and Password'), 'danger')

    return render_template('login.html', form=form)

@app.route('/dashboard')
def admin_dashboard():
    if not is_authenticated():
        flash(_('Unauthorized access. Please log in.'), 'danger')
        return redirect(url_for('admin_login'))
    try:
        student_data = list(collection.find())
        # Escape user-generated content using Markup to prevent XSS
        for student in student_data:
            student['first_name'] = Markup(student['first_name'])
            student['last_name'] = Markup(student['last_name'])
            student['phone'] = Markup(student['phone'])
            student['address'] = Markup(student['address'])
            student['pincode'] = Markup(student['pincode'])
            student['email'] = Markup(student['email'])
            student['gender'] = Markup(student['gender'])
            student['date_of_birth'] = Markup(student['date_of_birth'])
    except Exception as e:
        # Log detailed error for debugging
        logging.error(f'Error in admin_dashboard route: {str(e)}')
        # Display a user-friendly error message
        error_message = _('An error occurred while fetching student data. Please try again later.')
        # Enhance error handling: Detailed Errors
        return render_template('error.html', error_message=error_message, detailed_error=str(e), status_code=500)

    return render_template('dashboard.html', student_data=student_data)

@app.route('/edit_student/<student_id>', methods=['GET', 'POST'])
def edit_student(student_id):
    if not is_authenticated():
        flash(_('Unauthorized access. Please log in.'), 'danger')
        return redirect(url_for('admin_login'))

    # Create an instance of the StudentForm
    form = StudentForm()

    try:
        student = collection.find_one({'_id': ObjectId(student_id)})
    except Exception as e:
        flash(_('An error occurred: {str(e)}'), 'danger')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST' and form.validate_on_submit():
        try:
            collection.update_one(
                {'_id': ObjectId(student_id)},
                {
                    '$set': {
                        'first_name': form.first_name.data,
                        'last_name': form.last_name.data,
                        'phone': form.phone.data,
                        'address': form.address.data,
                        'pincode': form.pincode.data,
                        'date_of_birth': form.dob.data,
                    }
                }
            )
            flash(_('Student information updated successfully!'), 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            # Log detailed error for debugging
            logging.error(f'Error in edit_student route: {str(e)}')
            flash(_('An error occurred. Please try again later.'), 'danger')

    form.first_name.data = student['first_name']
    form.last_name.data = student['last_name']
    form.phone.data = student['phone']
    form.address.data = student['address']
    form.pincode.data = student['pincode']
    form.email.data = student['email']
    form.gender.data = student['gender']
    form.dob.data = student['date_of_birth']

    return render_template('edit_student.html', student=student, form=form)

@app.route('/delete_student/<student_id>')
def delete_student(student_id):
    if not is_authenticated():
        flash(_('Unauthorized access. Please log in.'), 'danger')
        return redirect(url_for('admin_login'))

    try:
        collection.delete_one({'_id': ObjectId(student_id)})
        flash(_('Student deleted successfully!'), 'success')
    except Exception as e:
        # Log detailed error for debugging
        logging.error(f'Error in delete_student route: {str(e)}')
        flash(_('An error occurred. Please try again later.'), 'danger')

    return redirect(url_for('admin_dashboard'))


@app.route('/logout')
def logout():
    session.pop('authenticated', None)
    return redirect(url_for('admin_login'))

if __name__ == '__main__':
    socketio.run(app, debug=True)
