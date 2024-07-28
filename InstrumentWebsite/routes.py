from flask import Flask, render_template, redirect, url_for, request, session, flash
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = 'secret'


# "hash_password" takes one parameter, "password", 
# which is the password that needs to be hashed 
# "hashlib.sha256(password.encode())" creates a new SHA-256 hash object and 
# hashes the encoded password
# ".hexdigest()" returns the hash as a hexadecimal string, 
# which is a human-readable representation of the binary hash

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def check_password(stored_password, provided_password):
    return stored_password == hash_password(provided_password)


def sql_queries(query, params, option):
    connection = sqlite3.connect('instruments.db')
    cursor = connection.cursor()
    cursor.execute(query, params)
    if option == 'fetchone':
        result = cursor.fetchone()
        connection.close()
        return result
    elif option == 'fetchall':
        result = cursor.fetchall()
        connection.close()
        return result
    elif option == 'commit':
        connection.commit()
        connection.close()


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Validation check
        if len(password) < 8 or not any(char.isdigit() for char in password) or not any(char.isupper() for char in password):
            flash("Password must be at least 8 characters long, must contain at least one digit, and must contain at least one uppercase letter", "error")
            return render_template('signup.html')

        # Check if username already exists
        existing_user = sql_queries("SELECT * FROM Users WHERE username = ?", (username,), 'fetchone')
        if existing_user:
            flash("Username already exists. Please choose a different one.", "error")
            return render_template('signup.html')

        # Add the user to the database
        hashed_password = hash_password(password)
        try:
            sql_queries("INSERT INTO Users (username, password) VALUES (?, ?)", (username, hashed_password), 'commit')
            flash("Account created successfully", "success")
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"An error occurred: {e}", "error")
            return render_template('signup.html')

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = sql_queries("SELECT * FROM Users WHERE username = ?", (username,), 'fetchone')

        if user and check_password(user[2], password):  # Replace check_password with your password checking logic
            session['user_id'] = user[0]  # Store user ID in session
            flash('Login successful!', 'success')
            return redirect(url_for('home'))  # Redirect to the home page
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logged out", "success")
    return redirect(url_for('home'))


@app.route('/add_comment/<int:instrument_id>', methods=['GET', 'POST'])
def add_comment(instrument_id):
    if 'user_id' not in session:
        flash("You must be logged in to add a comment.", "error")
        return redirect(url_for('login'))
    if request.method == 'POST':
        # Get comment and user_id from the form
        comment_text = request.form.get('comment')
        user_id = session.get('user_id')

        # Validation
        if not comment_text:
            flash('Comment cannot be empty.', 'error')
            return render_template('add_comment.html', instrument_id=instrument_id)

        # Insert the comment into the database
        else:
            query = "INSERT INTO Comment (instrument_id, user_id, unchecked_comment) VALUES (?, ?, ?);"
            try:
                sql_queries(query, (instrument_id, user_id, comment_text), 'commit')
                flash('Comment added successfully! Please wait for your comment to be profanity-checked ', 'success')
                return redirect(url_for('instrument_details', id=instrument_id))
            except Exception as e:
                flash(f"An error occurred: {e}", 'error')

    # Render the comment form
    return render_template('add_comment.html', instrument_id=instrument_id)


# Individual instrument details page.
@app.route('/instrument/<int:id>')
def instrument_details(id):
    # Fetch instrument details
    query_instrument = "SELECT * FROM Instrument WHERE id = ?"
    instrument = sql_queries(query_instrument, (id,), 'fetchone')
    
    # Check if instrument was found
    if not instrument:
        flash("Instrument not found.", "error")
        return redirect(url_for('home'))  # Redirect to home or another appropriate page

    # Fetch comments for the instrument
    query_comments = """
        SELECT checked_comment, username
        FROM Comments
        JOIN Users ON Comments.user_id = Users.id
        WHERE instrument_id = ?
    """
    comments = sql_queries(query_comments, (id,), 'fetchall')

    # Pass the instrument details and comments to the template
    return render_template("instrument.html", instrument=instrument, comments=comments)


@app.route('/string')
def string():
    search_term = request.args.get('search')
    if search_term:
        query = "SELECT * FROM Instrument WHERE familyid = 1 AND name LIKE ?"
        params = ('%' + search_term + '%',)
    else:
        query = "SELECT * FROM Instrument WHERE familyid = 1"
        params = ()
    results = sql_queries(query, params, 'fetchall')
    return render_template("string.html", results=results)


@app.route('/woodwind')
def woodwind():
    search_term = request.args.get('search')
    if search_term:
        query = "SELECT id, name FROM Instrument WHERE familyid = 2 AND name LIKE ?"
        params = ('%' + search_term + '%',)
    else:
        query = "SELECT id, name FROM Instrument WHERE familyid = 2"
        params = ()
    results = sql_queries(query, params, 'fetchall')
    return render_template("woodwind.html", results=results)


@app.route('/brass')
def brass():
    search_term = request.args.get('search')
    if search_term:
        query = "SELECT id, name FROM Instrument WHERE familyid = 3 AND name LIKE ?"
        params = ('%' + search_term + '%',)
    else:
        query = "SELECT id, name FROM Instrument WHERE familyid = 3"
        params = ()
    results = sql_queries(query, params, 'fetchall')
    return render_template("brass.html", results=results)


@app.route('/percussion')
def percussion():
    search_term = request.args.get('search')
    if search_term:
        query = "SELECT id, name FROM Instrument WHERE familyid = 4 AND name LIKE ?"
        params = ('%' + search_term + '%',)
    else:
        query = "SELECT id, name FROM Instrument WHERE familyid = 4"
        params = ()
    results = sql_queries(query, params, 'fetchall')
    return render_template("percussion.html", results=results)


if __name__ == '__main__':
    app.run(debug=True)
