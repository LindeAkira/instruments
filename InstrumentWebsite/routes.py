from flask import Flask, render_template
import sqlite3
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

app = Flask(__name__)


@app.route('/')
def homepage():
    return render_template("home.html")


@app.route('/signup, methods=["GET", "POST"]')
def signup():
    # If the user made a POST request, create a new user
    if request.method == "POST":
        user = Users(username=request.form.get("username"),
                     password=request.form.get("password"))
        # Add the user to the database
        db.session.add(user)
        # Commit the changes made
        db.session.commit()
        # Once user account created, redirect them
        # to login route (created later on)
        return redirect(url_for("login"))
    # Renders sign_up template if user made a GET request
    return render_template("sign_up.html")

@app.route('/login')
def login():
    return render_template("login.html")

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