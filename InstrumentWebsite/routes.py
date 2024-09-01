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

def validate_input(input_value, input_type):

    # Validates the input value for username or password.

    # Parameters:
    # - input_value (str): The value to validate (password or username).
    # - input_type (str): A string indicating the type of input ('password' or 'username').

    # Returns:
    # - str or None: Returns an error message if the validation fails, otherwise returns None.

    if len(input_value) < 8:
        return f"{input_type.capitalize()} must be at least 8 characters long."
    if len(input_value) > 50:
        return f"{input_type.capitalize()} must not exceed 50 characters."
    if input_type == 'password':
        if not any(char.isdigit() for char in input_value):
            return f"{input_type.capitalize()} must contain at least one digit."
        if not any(char.isupper() for char in input_value):
            return f"{input_type.capitalize()} must contain at least one uppercase letter."
    return None


@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Validate password
        password_error = validate_input(password, 'password')
        if password_error:
            flash(password_error, "error")
            return render_template('signup.html')

        # Validate username
        username_error = validate_input(username, 'username')
        if username_error:
            flash(username_error, "error")
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

    return render_template('signup.html', page='signup')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = sql_queries("SELECT * FROM Users WHERE username = ?", (username,), 'fetchone')

        if user and check_password(user[2], password):
            session['user_id'] = user[0]  # Store user ID in session
            return redirect(url_for('string'))  # Redirect to the string page
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html', page='login')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logged out", "success")
    return redirect(url_for('string'))


@app.route('/search')
def search():
    search_term = request.args.get('search', '').strip()  # Ensure search_term is a string and strip any whitespace
    
    if search_term:
        if len(search_term) > 50:
            # If the search term is too long, set the result as an error message and no results
            error_message = "Search term must be under 50 characters."
            search_term = None  # Clear the search term to prevent it from being displayed
            results = []  # No results will be shown
        else:
            query = """
            SELECT * FROM Instrument
            WHERE name LIKE ?
            """
            params = ('%' + search_term + '%',)
            results = sql_queries(query, params, 'fetchall')
            error_message = None  # No error
    else:
        query = "SELECT * FROM Instrument"
        params = ()
        results = sql_queries(query, params, 'fetchall')
        error_message = None  # No error
    
    # Debugging: Print the results to the console
    print("Search Term:", search_term)
    print("Results:", results)
    
    # Pass the error message to the template, if any
    return render_template("search_results.html", search_term=search_term, results=results, error_message=error_message)



@app.route('/comment/<int:instrument_id>', methods=['GET', 'POST'])
def add_comment(instrument_id):
    if request.method == 'POST':
        comment_text = request.form.get('comment')
        user_id = session.get('user_id')

        if not user_id:
            flash("You need to be logged in to add a comment.", "error")
            return redirect(url_for('login'))

        if not comment_text:
            flash("Comment cannot be empty.", "error")
            return render_template('add_comment.html', instrument_id=instrument_id)

        unchecked_comment = comment_text
        # Add comment to the database
        try:
            query = "INSERT INTO Comments (instrument_id, user_id, unchecked_comment, checked_comment) VALUES (?, ?, ?, ?)"
            params = (instrument_id, user_id, unchecked_comment, "")
            sql_queries(query, params, 'commit')
            flash("Comment added successfully and will be displayed after being profanity checked.", "success")
            return redirect(url_for('instrument_details', instrument_id=instrument_id))
        except Exception as e:
            flash(f"An error occurred: {e}", "error")
            return render_template('add_comment.html', instrument_id=instrument_id)

    return render_template('add_comment.html', instrument_id=instrument_id)


# Individual instrument details page.
@app.route('/instrument/<int:instrument_id>')
def instrument_details(instrument_id):
    # Fetch the instrument details
    instrument_query = "SELECT * FROM Instrument WHERE id = ?"
    instrument = sql_queries(instrument_query, (instrument_id,), 'fetchone')

    # Fetch the comments with usernames
    comments_query = """
    SELECT Comments.id, Comments.unchecked_comment, Comments.checked_comment, Users.username, Comments.user_id
    FROM Comments
    JOIN Users ON Comments.user_id = Users.id
    WHERE Comments.instrument_id = ?
    """
    comments = sql_queries(comments_query, (instrument_id,), 'fetchall')

    return render_template('instrument.html', instrument=instrument, comments=comments)


@app.route('/delete_comment/<int:comment_id>/<int:instrument_id>', methods=['POST'])
def delete_comment(comment_id, instrument_id):
    user_id = session.get('user_id')

    if not user_id:
        flash('You need to be logged in to delete your comment', 'error')
        return redirect(url_for('login'))
    
        # Check if the comment belongs to the logged-in user
    query = "SELECT user_id FROM Comments WHERE id = ?"
    comment = sql_queries(query, (comment_id,), 'fetchone')

    if comment and comment[0] == user_id:
        try:
            delete_query = "DELETE FROM Comments WHERE id = ?"
            sql_queries(delete_query, (comment_id,), 'commit')
            flash("Comment deleted successfully.", "success")
        except Exception as e:
            flash(f"An error occurred: {e}", "error")
    
    else:
        flash('You can only delete you own comments', 'error')

    return redirect(url_for('instrument_details', instrument_id=instrument_id))


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
    return render_template("string.html", page='string', results=results)


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
    return render_template("woodwind.html", page='woodwind', results=results)


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
    return render_template("brass.html", page='brass', results=results)


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
    return render_template("percussion.html", page='percussion', results=results)


if __name__ == '__main__':
    app.run(debug=True)
