from cs50 import SQL
from flask import Flask, render_template, request, session, redirect
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

# boilerplate
app = Flask('__name__')

# configure
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL('sqlite:///arcadia.db')

@app.route('/')
def index():
    if session.get("user_id") == None:
            return redirect("/login")
    actual_name = db.execute('SELECT * FROM users WHERE id = ?', session['user_id'])[0]['name'].title()

    received = db.execute('SELECT * FROM mails JOIN users ON users.id = sender_id WHERE receiver_id = ?', session['user_id'])

    return render_template('index.html', actual_name=actual_name, received=received)


@app.route('/login', methods=['GET', 'POST'])
def login():
    session.clear()

    if request.method == 'GET':
        return render_template('login.html')
    else:
        name = request.form.get('name')
        password = request.form.get('password')
        user = db.execute('SELECT * FROM users WHERE name = ?', name)

        # validation
        if not name or not password:
            return render_template('login.html', error='Fill in all fields')
        # check if the user is in the database
        elif not user:
            return render_template('login.html', error='The user does not exist')
        # check if passwords match
        elif len(user) != 1 or not check_password_hash(user[0]["password"], password):
            return render_template('login.html', error='Wrong password')

        session['user_id'] = user[0]['id']

        return redirect('/')


@app.route('/register', methods=['GET', 'POST'])
def register():
    session.clear()

    if request.method == 'GET':
        return render_template('register.html')

    else:
        name = request.form.get('name')
        password = request.form.get('password')
        confirmation = request.form.get('confirm-password')
        users = db.execute('SELECT * FROM users WHERE name = ?', name)

        # validation
        if not name or not password or not confirmation:
            return render_template('register.html', error='Fill in all fields')
        elif password != confirmation:
            return render_template('register.html', error='The passwords don\'t match')
        # check if user already exists
        elif users:
            return render_template('register.html', error='The username already exists')
        # len limit
        elif len(name) > 12:
            return render_template('register.html', error='The maximum number of characters is 12')

        # insert into database and give cookie
        db.execute('INSERT INTO users(name, password) VALUES(?, ?)', name, generate_password_hash(password))

        session['user_id'] = db.execute('SELECT * FROM users WHERE name = ?', name)[0]['id']

        return redirect('/')


@app.route('/send', methods=['GET', 'POST'])
def send():
    if session.get("user_id") == None:
            return redirect("/login")
    actual_name = db.execute('SELECT * FROM users WHERE id = ?', session['user_id'])[0]['name'].title()

    if request.method == 'GET':
        return render_template('send.html', actual_name=actual_name)
    else:
        name = request.form.get('username')
        message = request.form.get('message')
        users = db.execute('SELECT * FROM users WHERE name = ?', name)

        # validation
        if not name:
            return render_template('send.html', actual_name=actual_name, error1='Fill the field')
        elif not message:
            return render_template('send.html', actual_name=actual_name, error2='Fill the field')
        elif not users:
            return render_template('send.html', actual_name=actual_name, error1='The user does not exist')
        # len message
        elif len(message) > 100:
            return render_template('send.html', actual_name=actual_name, error2='The maximum number of characters is 100')

        # insert info into emails
        sender_id = session['user_id']
        receiver_id = users[0]['id']
        text = message
        date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        db.execute('INSERT INTO mails(sender_id, receiver_id, message, date) VALUES(?, ?, ?, ?)',
                   sender_id, receiver_id, text, date)

        return redirect('/')

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if session.get("user_id") == None:
            return redirect("/login")
    actual_name = db.execute('SELECT * FROM users WHERE id = ?', session['user_id'])[0]['name'].title()

    if request.method == 'GET':
        return render_template('settings.html', actual_name=actual_name)
    else:
        actualUser = db.execute('SELECT * from users WHERE id = ?', session['user_id'])


        # identify if that is the username form
        if 'new-username' in request.form:
            newName = request.form.get('new-username')
            users = db.execute('SELECT * FROM users WHERE name = ?', newName)

            # validation
            if not newName:
                return render_template('settings.html', actual_name=actual_name, error1='Fill the field')
            elif users:
                return render_template('settings.html', actual_name=actual_name, error1='User already exists')

            # change database
            db.execute('UPDATE users SET name = ? WHERE id = ?', newName, session['user_id'])

            return redirect('/')

        # identify if that is the password form
        else:
            oldPassword = request.form.get('old-password')
            newPassword = request.form.get('new-password')

            # validation
            if not oldPassword or not newPassword:
                return render_template('settings.html', actual_name=actual_name, error2='Fill all fields')
            elif not check_password_hash(actualUser[0]["password"], oldPassword):
                return render_template('settings.html', actual_name=actual_name, error2='Wrong password')
            elif oldPassword == newPassword:
                return render_template('settings.html', actual_name=actual_name, error2='The passwords are the same')

            # change database
            db.execute('UPDATE users SET password = ? WHERE id = ?', generate_password_hash(newPassword), session['user_id'])

            return redirect('/')
