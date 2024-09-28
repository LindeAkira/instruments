import hashlib


import sqlite3


from flask import Flask, flash, redirect, render_template, request, session, url_for, abort


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
    
    Takes the input and which of username of password it is.
    Checks if it is valid by checking the length and what it contains e.g. digit, uppercase.
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


# Error pages for page not found, url too long, server error
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(414)
def request_uri_too_long(e):
    return render_template('414.html'), 414


@app.errorhandler(500)
def internal_server_error(error):
    return render_template("500.html"), 500


# Used to test the 500 error
@app.route('/trigger-error')
def trigger_error():
    raise Exception("This is a test error")


@app.before_request
def limit_url_length():
    MAX_URL_LENGTH = 200  # Set your URL length limit
    if len(request.path) > MAX_URL_LENGTH:
        abort(414)


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
                "INSERT INTO Users (username, password, admin) VALUES (?, ?, 0)",
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

            # Retrieve and pop the original page URL
            next_page = session.pop('next', None)
            flash("Successfully logged in!", "success")
            return redirect(next_page or url_for('string'))  # Redirect to the next page or a default page

        else:
            flash('Invalid username or password.', 'error')

    return render_template('login.html', page='login')


@app.route('/logout')
def logout():
    # The parameter None is passed to not raise an error if the user logs out without logging in
    session.clear()  # clear all session data
    flash("You have been logged out", "success")
    return redirect(url_for('string'))


@app.route('/search')
def search():
    # Removes any spaces from the beginning and end
    search_term = request.args.get('search', '').strip()
    
    if search_term:
        if len(search_term) > 50:
            error_message = "Search term must be under 50 characters."
            search_term = None
            results = []
        else:
            # Valid input, proceed with search and order the results alphabetically
            query = "SELECT id, name, image FROM Instrument WHERE name LIKE ? ORDER BY name"
            params = ('%' + search_term + '%',)
            results = sql_queries(query, params, 'fetchall')
            error_message = None
    else:
        # If the search term is empty (after stripping spaces)
        error_message = "Please enter a valid search term."
        results = []
        search_term = None

    return render_template(
        "search_results.html", search_term=search_term, results=results,
        error_message=error_message
    )


@app.route('/instrument/<int:instrument_id>')
def instrument_details(instrument_id):
    try:
        # If the user is not logged in, store the current URL in the session before redirecting
        if 'user_id' not in session:
            session['next'] = request.url
        
        # Check if the instrument_id exists in the database
        query = "SELECT COUNT(1) FROM Instrument WHERE id = ?"
        instrument_exists = sql_queries(query, (instrument_id,), 'fetchone')
        if not instrument_exists or not instrument_exists[0]:  # No instrument found
            raise KeyError

        instrument_query = """
        SELECT Instrument.id, Instrument.name, Instrument.description,
        Instrument.image, InstrumentFamily.id, InstrumentFamily.name
        FROM Instrument
        JOIN InstrumentFamily ON Instrument.familyid = InstrumentFamily.id
        WHERE Instrument.id = ?
        """
        instrument = sql_queries(instrument_query, (instrument_id,), 'fetchone')

        if instrument is None:
            abort(404)

        # Query comments related to the instrument where comment_status is 1
        comments_query = """
        SELECT Comments.id, Comments.comment, Users.username, Comments.user_id
        FROM Comments
        JOIN Users ON Comments.user_id = Users.id
        WHERE Comments.instrument_id = ? AND Comments.comment_status = 1
        """
        comments = sql_queries(comments_query, (instrument_id,), 'fetchall')

        return render_template('instrument.html', instrument=instrument, comments=comments)

    except KeyError:
        abort(404)

    except Exception as e:
        print(f"General Exception occurred: {e}")
        abort(500, description=str(e))


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
            return render_template('add_comment.html', instrument_id=instrument_id)

        comment = comment_text
        try:
            # Check if the instrument_id exists in the database
            query = "SELECT COUNT(1) FROM Instrument WHERE id = ?"
            instrument_exists = sql_queries(query, (instrument_id,), 'fetchone')
            if not instrument_exists or not instrument_exists[0]:  # No instrument found
                # Using KeyError as a scapegoat if no instrument is found
                raise KeyError
            
            # Inserting comment into database
            query = """
            INSERT INTO Comments (instrument_id, user_id, comment, comment_status) 
            VALUES (?, ?, ?, ?)
            """
            params = (instrument_id, user_id, comment, 0)
            sql_queries(query, params, 'commit')
            flash("Comment added and will display after profanity check.", "success")
            return redirect(url_for('instrument_details', instrument_id=instrument_id))
        
        except ValueError:
            abort(414)

        except OverflowError:
            abort(414)

        # This is where the error of no instrument leads
        except KeyError:
            abort(404)
            
        except Exception as e:
            abort(500, description=str(e))

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

        current_status_query = "SELECT comment_status FROM Comments WHERE id = ?"
        current_status = sql_queries(current_status_query, (comment_id,), 'fetchone')[0]

        # Only update if the new status is different from the current status
        if str(current_status) != new_status:
            update_query = "UPDATE Comments SET comment_status = ? WHERE id = ?"
            sql_queries(update_query, (new_status, comment_id), 'commit')
            flash("Comment status updated successfully.", 'success')
        else:
            flash("No changes were made.", 'info')

        return redirect(url_for('admin_comments'))

    return render_template('admin_comments.html', comments=comments)


@app.route('/delete_comment/<int:comment_id>/<int:instrument_id>', methods=['POST', 'GET'])
def delete_comment(comment_id, instrument_id):
    # Checks if they are typing it into the URL
    if request.method == 'GET':
        flash('Invalid request method.', 'error')
        return redirect(url_for('instrument_details', instrument_id=instrument_id))

    user_id = session.get('user_id')

    # Checks that the user is the owner of the comment
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


# Route for String Instruments
@app.route('/')
@app.route('/string')
def string():
    # Search form
    search_term = request.args.get('search', '').strip()
    
    if search_term:
        if len(search_term) > 50:
            flash("Search term must be under 50 characters.", "error")
            search_term = None  # Clear the search term to prevent a query
            results = []  # No results should be shown
        else:
            query = """
            SELECT id, name, image FROM Instrument 
            WHERE familyid = 1 AND name LIKE ? 
            ORDER BY name
            """
            params = ('%' + search_term + '%',)
            results = sql_queries(query, params, 'fetchall')
    else:
        # Display all string instruments, ordered alphabetically
        query = "SELECT id, name, image FROM Instrument WHERE familyid = 1 ORDER BY name"
        params = ()
        results = sql_queries(query, params, 'fetchall')

    return render_template("string.html", page='string', results=results)


# Route for Woodwind Instruments
@app.route('/woodwind')
def woodwind():
    search_term = request.args.get('search', '').strip()

    if search_term:
        if len(search_term) > 50:
            flash("Search term must be under 50 characters.", "error")
            search_term = None
            results = []
        else:
            query = """
            SELECT id, name, image FROM Instrument 
            WHERE familyid = 2 AND name LIKE ? 
            ORDER BY name
            """
            params = ('%' + search_term + '%',)
            results = sql_queries(query, params, 'fetchall')
    else:
        query = "SELECT id, name, image FROM Instrument WHERE familyid = 2 ORDER BY name"
        params = ()
        results = sql_queries(query, params, 'fetchall')

    return render_template("woodwind.html", page='woodwind', results=results)


# Route for Brass Instruments
@app.route('/brass')
def brass():
    search_term = request.args.get('search')

    if search_term:
        if len(search_term) > 50:
            flash("Search term must be under 50 characters.", "error")
            search_term = None  # Clear the search term to prevent a query
            results = []  # No results should be shown
        else:
            query = """
            SELECT id, name, image FROM Instrument 
            WHERE familyid = 3 AND name LIKE ? 
            ORDER BY name
            """
            params = ('%' + search_term + '%',)
            results = sql_queries(query, params, 'fetchall')
    else:
        query = "SELECT id, name, image FROM Instrument WHERE familyid = 3 ORDER BY name"
        params = ()
        results = sql_queries(query, params, 'fetchall')

    return render_template("brass.html", page='brass', results=results)


# Route for Percussion Instruments
@app.route('/percussion')
def percussion():
    search_term = request.args.get('search')

    if search_term:
        if len(search_term) > 50:
            flash("Search term must be under 50 characters.", "error")
            search_term = None  # Clear the search term to prevent a query
            results = []  # No results should be shown
        else:
            query = """
            SELECT id, name, image FROM Instrument 
            WHERE familyid = 4 AND name LIKE ? 
            ORDER BY name
            """
            params = ('%' + search_term + '%',)
            results = sql_queries(query, params, 'fetchall')
    else:
        query = "SELECT id, name, image FROM Instrument WHERE familyid = 4 ORDER BY name"
        params = ()
        results = sql_queries(query, params, 'fetchall')

    return render_template("percussion.html", page='percussion', results=results)


if __name__ == '__main__':
    app.run(debug=True)
