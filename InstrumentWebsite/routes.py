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


def sql_queries(query, option):
    connection = sqlite3.connect('toast.db')
    cursor = connection.cursor()
    cursor.execute(query)
    if option == 'fetchone':
        result = cursor.fetchone()
        return result
    elif option == 'fetchall':
        result = cursor.fetchall()
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
        
        
        # if len(password) < 8:
        #     flash("Password must be at least 8 characters long", "error")
        #     return render_template('signup.html')
        # if not any(char.isdigit() for char in password):
        #     flash("Password must contain at least one digit", "error")
        #     return render_template('signup.html')
        # if not any(char.isupper() for char in password):
        #     flash("Password must contain at least one uppercase letter", "error")
        #     return render_template('signup.html')

        # Check if username already exists
        conn = sqlite3.connect("instruments.db")
        cur = conn.cursor()
        cur.execute("SELECT * FROM User WHERE username = ?", (username,))
        existing_user = cur.fetchone()
        if existing_user:
            flash("Username already exists. Please choose a different one.", "error")
            conn.close()
            return render_template('signup.html')

        # Add the user to the database
        hashed_password = hash_password(password)
        try:
            cur.execute("INSERT INTO User (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            flash("Account created successfully", "success")
            return redirect(url_for('login'))
        except Exception as e:
            conn.rollback()
            flash(f"An error occurred: {e}", "error")
            return render_template('signup.html')
        finally:
            conn.close()

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect("instruments.db")
        cur = conn.cursor()
        cur.execute("SELECT * FROM User WHERE username = ?", (username,))
        user = cur.fetchone()
        conn.close()

        if user and check_password(user[2], password):
            session['username'] = username
            flash("Login successful", "success")
            return redirect(url_for('string'))
        flash('Invalid credentials', 'error')
    return render_template('login.html')


@app.route('/')
def lobby():
    if 'username' in session:
        return f'Logged in as {session["username"]}'
    return render_template('lobby.html')


@app.route('/home')
def home():
    return render_template('home.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("You have been logged out", "success")
    return redirect(url_for('lobby'))


@app.route('/comment/<int:instrument_id>', methods=['GET', 'POST'])
def add_comment(instrument_id):
    if request.method == 'POST':
        # Get comment and user_id from the form
        comment_text = request.form.get('comment')
        user_id = 1  # Replace with logic to get the actual user ID

        # Validation
        if not comment_text:
            flash('Comment cannot be empty.', 'error')
            return render_template('add_comment.html', instrument_id=instrument_id)

        # Insert the comment into the database
        query = "INSERT INTO Comments (instrument_id, user_id, unchecked_comment) VALUES (?, ?, ?);"
        try:
            sql_queries(query, (instrument_id, user_id, comment_text), 'commit')
            flash('Comment added successfully!', 'success')
            return redirect(url_for('instrument_details', id=instrument_id))
        except Exception as e:
            flash(f"An error occurred: {e}", 'error')

    # Render the comment form
    return render_template('add_comment.html', instrument_id=instrument_id)


# Individual instrument details page.
@app.route('/instrument/<int:id>')
def instrument_details(id):
    # Define queries
    instrument_query = "SELECT * FROM Instrument WHERE id = ?;"
    comments_query = """
        SELECT Comments.unchecked_comment, Comments.checked_comment, Users.username
        FROM Comments
        JOIN Users ON Comments.user_id = Users.id
        WHERE Comments.instrument_id = ?;
    """
    # Fetch instrument details
    instrument = sql_queries(instrument_query, (id,), 'fetchone')

    # Fetch comments for the specific instrument
    comments = sql_queries(comments_query, (id,), 'fetchall')

    return render_template("instrument.html", instrument=instrument, comments=comments)


@app.route('/string')
def string():
    conn = sqlite3.connect('instruments.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Instrument WHERE familyid = 1")
    string = cursor.fetchall()
    print(string)
    return render_template("string.html", results=string)


@app.route('/woodwind')
def woodwind():
    conn = sqlite3.connect('instruments.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Instrument WHERE familyid = 2")
    woodwind = cursor.fetchall()
    return render_template("woodwind.html", results=woodwind)


@app.route('/brass')
def brass():
    conn = sqlite3.connect('instruments.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Instrument WHERE familyid = 3")
    brass = cursor.fetchall()
    return render_template("brass.html", results=brass)


@app.route('/percussion')
def percussion():
    conn = sqlite3.connect('instruments.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Instrument WHERE familyid = 4")
    percussion = cursor.fetchall()
    return render_template("percussion.html", results=percussion)


if __name__ == '__main__':
    app.run(debug=True)
