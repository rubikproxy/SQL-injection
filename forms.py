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
from flask import render_template, abort


app = Flask(__name__)

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

client = MongoClient('mongodb+srv://finalyear:68VBgQHEehmm0mJ4@cluster0.oz1cn45.mongodb.net/')
db = client['student_database']
collection = db['student_collection']

# Use hashed passwords
admin_username = 'sanjay'
admin_password_hash = generate_password_hash('sanjay', method='sha256')
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[validators.InputRequired()])
    password = PasswordField('Password', validators=[validators.InputRequired()])
    submit = SubmitField('Login')

class StudentForm(FlaskForm):
    first_name = StringField('First Name', validators=[validators.InputRequired()])
    last_name = StringField('Last Name', validators=[validators.InputRequired()])
    phone = StringField('Phone', validators=[validators.InputRequired()])
    address = StringField('Address', validators=[validators.InputRequired()])
    pincode = StringField('Pincode', validators=[validators.InputRequired()])
    email = StringField('Email', validators=[validators.InputRequired(), validators.Email()])
    gender = StringField('Gender', validators=[validators.InputRequired()])
    dob = StringField('Date of Birth', validators=[validators.InputRequired()])
    submit = SubmitField('Submit')

def is_authenticated():
    return session.get('authenticated', False)

@app.errorhandler(404)
def page_not_found(error):
    return render_template('error.html', error_message='Page not found', status_code=404), 404

# Define a custom error handler for 500 Internal Server Error
@app.errorhandler(500)
def internal_server_error(error):
    return render_template('error.html', error_message='Internal Server Error', status_code=500), 500

# Define a custom error handler for other exceptions
@app.errorhandler(Exception)
def handle_exception(error):
    return render_template('error.html', error_message=str(error), status_code=500), 500


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
            flash('Thank you for your submission!', 'success')
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'danger')

        return redirect(url_for('index'))
    else:
        flash('Invalid input. Please check your entries.', 'danger')
        return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def admin_login():
    form = LoginForm()  # Create an instance of the LoginForm
    if request.method == 'POST' and form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Use hashed passwords for comparison
        if username == admin_username and check_password_hash(admin_password_hash, password):
            session['authenticated'] = True
        else:
            return 'Invalid Username and Passwoard'
        return redirect(url_for('admin_dashboard'))

    return render_template('login.html', form=form)

@app.route('/dashboard')
def admin_dashboard():
    if not is_authenticated():
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
        error_message = f'An error occurred: {str(e)}'
        return render_template('error.html', error_message=error_message)

    return render_template('dashboard.html', student_data=student_data)

@app.route('/edit_student/<student_id>', methods=['GET', 'POST'])
def edit_student(student_id):
    if not is_authenticated():
        return redirect(url_for('admin_login'))

    # Create an instance of the StudentForm
    form = StudentForm()

    try:
        student = collection.find_one({'_id': ObjectId(student_id)})
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'danger')
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
            flash('Student information updated successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'danger')


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
        return redirect(url_for('admin_login'))

    try:
        collection.delete_one({'_id': ObjectId(student_id)})
        flash('Student deleted successfully!', 'success')
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'danger')

    return redirect(url_for('admin_dashboard'))

@app.route('/logout')
def logout():
    session.pop('authenticated', None)
    return redirect(url_for('admin_login'))

if __name__ == '__main__':
    app.run(debug=True)
