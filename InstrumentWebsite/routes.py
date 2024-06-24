from flask import Flask, render_template, redirect, url_for, request, session, flash
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = 'secret'


# "hash_password" takes one parameter, "password", which is the password that needs to be hashed. 
# "hashlib.sha256(password.encode())" creates a new SHA-256 hash object and hashes the encoded password. 
# ".hexdigest()" returns the hash as a hexadecimal string, which is a human-readable representation of the binary hash.

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def check_password(stored_password, provided_password):
    return stored_password == hash_password(provided_password)


@app.route('/')
def homepage():
    if 'username' in session:
        return f'Logged in as {session["username"]}'
    else:
        'You are not logged in'
    return render_template("home.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    # If the user made a POST request, create a new user
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        '''Validation check:'''
        if len(password) < 8 or not any(char.isdigit() for char in password) or not any(char.isupper() for char in password):
            flash("Password must be at least 8 characters long and contain at least one digit and one uppercase letter")
            render_template('signup.html')
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
            return render_template('signup.html', e)
        finally:
            conn.close()
    return render_template("signup.html")

        
    # Renders sign_up template if user made a GET request
    return render_template("signup.html")


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
            return redirect(url_for('string'))
        else:
            flash('Invalid credentials', 'error')
    return render_template('login.html')

# Individual instrument details page.
@app.route('/instrument/<int:id>')
def instrument_details(id):
    # print("The instrument id is {}".format(id))  # DEBUG
    conn = sqlite3.connect("instruments.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM Instrument WHERE id=?;", (id,))
    # fetchone returns a tuple containing the data for one entry
    instrument = cur.fetchone()
    conn.close()
    return render_template("instrument.html", instrument=instrument)


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

# must be the last two lines of code for website
if __name__ == '__main__':
    app.run(debug=True)