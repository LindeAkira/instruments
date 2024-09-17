import hashlib
import sqlite3

from flask import (
    Flask, flash, redirect, render_template, request, session, url_for
)


app = Flask(__name__)
app.secret_key = 'secret'


def hash_password(password):
    """Hashes a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()


def check_password(stored_password, provided_password):
    """Checks if the provided password matches the stored password."""
    return stored_password == hash_password(provided_password)


def sql_queries(query, params, option):
    """Executes SQL queries with different options (fetchone, fetchall, commit)."""
    connection = sqlite3.connect('instruments.db')
    cursor = connection.cursor()
    cursor.execute(query, params)

    if option == 'fetchone':
        result = cursor.fetchone()
    elif option == 'fetchall':
        result = cursor.fetchall()
    elif option == 'commit':
        connection.commit()
        result = None

    connection.close()
    return result


def validate_input(input_value, input_type):
    """
    Validates the input value for username or password.
    
    Parameters:
        input_value (str): The value to validate (password or username).
        input_type (str): A string indicating the type of input ('password' or 'username').
    
    .capotalize capitalises the first character of the string
    
    Returns:
        str or None: An error message if validation fails, otherwise None.

    """
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

# 414 handler, just in case
@app.errorhandler(414)
def request_uri_too_long(e):
    return render_template('414.html'), 414


@app.errorhandler(500)
def internal_server_error(error):
    return render_template("500.html"), 500


@app.route('/trigger-error')
def trigger_error():
    raise Exception("This is a test error")


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
        existing_user = sql_queries(
            "SELECT * FROM Users WHERE username = ?", (username,), 'fetchone'
        )
        if existing_user:
            flash("Username already exists. Please choose a different one.", "error")
            return render_template('signup.html')

        # Add the user to the database
        hashed_password = hash_password(password)
        try:
            sql_queries(
                "INSERT INTO Users (username, password) VALUES (?, ?)",
                (username, hashed_password),
                'commit'
            )
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

        user = sql_queries(
            "SELECT * FROM Users WHERE username = ?", (username,), 'fetchone'
        )

        if user and check_password(user[2], password):  # Check password validity
            session['user_id'] = user[0]  # Store user ID in session

            # Check if the user is an admin
            if user[3] == 1:
                session['is_admin'] = True

            # Debugging: print the session to see if is_admin and user_id are set
            print(session)  # Add this line here for debugging

            flash("Successfully logged in!", "success")
            return redirect(url_for('string'))  # Redirect to the string page
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html', page='login')



@app.route('/logout')
def logout():
    # The parameter None is passed to not raise an error if the user logs out without logging in
    session.pop('user_id', None)
    flash("You have been logged out", "success")
    return redirect(url_for('string'))


@app.route('/search')
def search():
    # Removes any space from the end
    search_term = request.args.get('search', '').strip()
    
    if search_term:
        if len(search_term) > 50:
            error_message = "Search term must be under 50 characters."
            search_term = None
            results = []
        else:
            query = "SELECT * FROM Instrument WHERE name LIKE ?"
            params = ('%' + search_term + '%',)
            # %: Matches any sequence of characters, including an empty sequence.
            # For example, %abc% matches any string that contains it such as abc, 123abc456
            results = sql_queries(query, params, 'fetchall')
            error_message = None
    else:
        query = "SELECT * FROM Instrument"
        params = ()
        results = sql_queries(query, params, 'fetchall')
        error_message = None

    return render_template(
        "search_results.html", search_term=search_term, results=results,
        error_message=error_message
    )


@app.route('/instrument/<int:instrument_id>')
def instrument_details(instrument_id):
    try:
        instrument_query = "SELECT * FROM Instrument WHERE id = ?"
        instrument = sql_queries(instrument_query, (instrument_id,), 'fetchone')

        if instrument is None:
            return render_template('404.html'), 404

        # Query comments related to the instrument where comment_status is 1
        comments_query = """
        SELECT Comments.id, Comments.comment, Users.username, Comments.user_id
        FROM Comments
        JOIN Users ON Comments.user_id = Users.id
        WHERE Comments.instrument_id = ? AND Comments.comment_status = 1
        """
        comments = sql_queries(comments_query, (instrument_id,), 'fetchall')

        return render_template('instrument.html', instrument=instrument, comments=comments)

    except ValueError:
        return render_template('414.html'), 414
    except OverflowError:
        return render_template('414.html'), 414
    except Exception as e:
        return render_template('500.html', error_message=str(e)), 500


@app.route('/comment/<int:instrument_id>', methods=['GET', 'POST'])
def add_comment(instrument_id):
    user_id = session.get('user_id')

    if not user_id:
        flash("You need to be logged in to add a comment.", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        comment_text = request.form.get('comment')

        if not comment_text:
            flash("Comment cannot be empty.", "error")
            return render_template('add_comment.html', 
                                   instrument_id=instrument_id)

        unchecked_comment = comment_text
        try:
            query = """
            INSERT INTO Comments (instrument_id, user_id, unchecked_comment, checked_comment) 
            VALUES (?, ?, ?, ?)
            """
            params = (instrument_id, user_id, unchecked_comment, "")
            sql_queries(query, params, 'commit')
            flash("Comment added successfully and will be displayed after being profanity checked.", "success")
            return redirect(url_for('instrument_details', instrument_id=instrument_id))
        except Exception as e:
            flash(f"An error occurred: {e}", "error")
            return render_template('add_comment.html', instrument_id=instrument_id)

    return render_template('add_comment.html', instrument_id=instrument_id)


@app.route('/admin/comments', methods=['GET', 'POST'])
def admin_comments():
    # Check if the user is an admin
    if not session.get('is_admin'):
        flash("You do not have permission to view this page.", 'error')
        return redirect(url_for('string'))

    # Fetch all comments and order by instrument_id
    comments_query = """
    SELECT Comments.id, Comments.comment, Comments.comment_status, 
           Users.username, Instrument.name, Comments.instrument_id
    FROM Comments
    JOIN Users ON Comments.user_id = Users.id
    JOIN Instrument ON Comments.instrument_id = Instrument.id
    ORDER BY Comments.instrument_id
    """
    comments = sql_queries(comments_query, (), 'fetchall')

    if request.method == 'POST':
        comment_id = request.form.get('comment_id')
        new_status = request.form.get('status')

        # Update the comment status in the database
        update_query = "UPDATE Comments SET comment_status = ? WHERE id = ?"
        sql_queries(update_query, (new_status, comment_id), 'commit')

        flash('Comment status updated successfully.', 'success')
        return redirect(url_for('admin_comments'))

    return render_template('admin_comments.html', comments=comments)




@app.route('/delete_comment/<int:comment_id>/<int:instrument_id>', methods=['POST'])
def delete_comment(comment_id, instrument_id):
    user_id = session.get('user_id')

    if not user_id:
        flash('You need to be logged in to delete your comment', 'error')
        return redirect(url_for('login'))
    
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
        flash('You can only delete your own comments', 'error')

    return redirect(url_for('instrument_details', instrument_id=instrument_id))


@app.route('/string')
def string():
    search_term = request.args.get('search', '').strip()
    
    if search_term:
        if len(search_term) > 50:
            flash("Search term must be under 50 characters.", "error")
            search_term = None
            results = []
        else:
            query = "SELECT * FROM Instrument WHERE familyid = 1 AND name LIKE ?"
            params = ('%' + search_term + '%',)
            results = sql_queries(query, params, 'fetchall')
    else:
        query = "SELECT * FROM Instrument WHERE familyid = 1"
        params = ()
        results = sql_queries(query, params, 'fetchall')

    return render_template("string.html", page='string', results=results) 


@app.route('/woodwind')
def woodwind():
    search_term = request.args.get('search', '').strip()

    if search_term:
        if len(search_term) > 50:
            flash("Search term must be under 50 characters.", "error")
            search_term = None
            results = []
        else:
            query = "SELECT * FROM Instrument WHERE familyid = 2 AND name LIKE ?"
            params = ('%' + search_term + '%',)
            results = sql_queries(query, params, 'fetchall')
    else:
        query = "SELECT * FROM Instrument WHERE familyid = 2"
        params = ()
        results = sql_queries(query, params, 'fetchall')

    return render_template("woodwind.html", page='woodwind', results=results)


@app.route('/brass')
def brass():
    search_term = request.args.get('search')
    if search_term:
        if len(search_term) > 50:
            flash("Search term must be under 50 characters.", "error")
            search_term = None  # Clear the search term to prevent a query
            results = []  # No results should be shown
        else:
            query = "SELECT * FROM Instrument WHERE familyid = 3 AND name LIKE ?"
            params = ('%' + search_term + '%',)
            results = sql_queries(query, params, 'fetchall')
    else:
        query = "SELECT id, name FROM Instrument WHERE familyid = 3"
        params = ()
        results = sql_queries(query, params, 'fetchall')

    # Debugging: Print the results to the console
    print("Search Term:", search_term)
    print("Results:", results)

    return render_template("brass.html", page='brass', results=results)


@app.route('/percussion')
def percussion():
    search_term = request.args.get('search')
    if search_term:
        if len(search_term) > 50:
            flash("Search term must be under 50 characters.", "error")
            search_term = None  # Clear the search term to prevent a query
            results = []  # No results should be shown
        else:
            query = "SELECT * FROM Instrument WHERE familyid = 4 AND name LIKE ?"
            params = ('%' + search_term + '%',)
            results = sql_queries(query, params, 'fetchall')
    else:
        query = "SELECT id, name FROM Instrument WHERE familyid = 4"
        params = ()
        results = sql_queries(query, params, 'fetchall')

    # Debugging: Print the results to the console
    print("Search Term:", search_term)
    print("Results:", results)

    return render_template("percussion.html", page='percussion', results=results)


if __name__ == '__main__':
    app.run(debug=True)
