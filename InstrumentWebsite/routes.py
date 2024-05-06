from flask import Flask, render_template
import sqlite3

app = Flask(__name__)


@app.route('/')
def homepage():
    return render_template("home.html")


@app.route('/about')
def about():
    return 'about :)'


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