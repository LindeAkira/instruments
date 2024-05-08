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

@app.route('/string')
def string():
    conn = sqlite3.connect('instruments.db')
    cur = conn.cursor()
    cur.execute("SELECT * FROM Instruments WHERE familyid = 1")
    return render_template("string.html")

@app.route('/woodwind')
def woodwind():
    return render_template("woodwind.html")

@app.route('/brass')
def brass():
    return render_template("brass.html")

@app.route('/percussion')
def percussion():
    return render_template("percussion.html")

@app.route('/instruments/<int:id>')
def pizza(id):
    conn = sqlite3.connect('instruments.db')
    cur = conn.cursor()
    cur.execute("SELECT * FROM Instruments WHERE id = ?", (id,))
    pizza = cur.fetchone()
    return render_template('pizza.html', pizza=pizza)


# must be the last two lines of code for website
if __name__ == '__main__':
    app.run(debug=True)