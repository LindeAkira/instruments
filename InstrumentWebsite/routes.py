from flask import Flask, render_template
import sqlite3

app = Flask(__name__)


@app.route('/home')
def homepage():
    return render_template("home.html")


@app.route('/signup')
def signup():
    return render_template("signup.html")

@app.route('/login')
def login():
    return render_template("login.html")

@app.route('/comments')
def comments():
    instr = 
    return render_template("comments.html")

@app.route('/string')
def string():
    conn = sqlite3.connect('instruments.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Instrument WHERE familyid = 1")
    string = cursor.fetchall()
    return render_template("string.html", string=string)

@app.route('/woodwind')
def woodwind():
    conn = sqlite3.connect('instruments.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Instrument WHERE familyid = 2")
    woodwind = cursor.fetchall()
    return render_template("woodwind.html", woodwind=woodwind)

@app.route('/brass')
def brass():
    conn = sqlite3.connect('instruments.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Instrument WHERE familyid = 3")
    brass = cursor.fetchall()
    return render_template("brass.html", brass=brass)

@app.route('/percussion')
def percussion():
    conn = sqlite3.connect('instruments.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Instrument WHERE familyid = 4")
    percussion = cursor.fetchall()
    return render_template("percussion.html", percussion=percussion)

# must be the last two lines of code for website
if __name__ == '__main__':
    app.run(debug=True)