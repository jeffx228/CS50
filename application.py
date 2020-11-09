import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# API_KEY=pk_7acdb5ee15594aba835d864c4a553194

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    my_net = 0
    entries = db.execute("SELECT * FROM stonks WHERE user_id = ?", session["user_id"])
    for row in entries:
        value = lookup(row["symbol"])
        db.execute("UPDATE stonks SET price = ? WHERE user_id = ? AND symbol = ?", value["price"], session["user_id"], value["symbol"])
        my_net += row["shares"] * value["price"]

    my_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
    my_net += my_cash

    entries = db.execute("SELECT * FROM stonks WHERE user_id = ?", session["user_id"])

    return render_template("index.html", my_cash = my_cash, my_net = my_net, entries = entries)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        # receives quote
        buy = request.form.get("buy")

        # checks if this is a real quote
        if (lookup(buy) is None):
            return apology("Please enter in a valid stock abbreviation", 403)

        shares = request.form.get("shares")

        share_price = lookup(buy)["price"]

        balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

        if not (shares.isdigit()):
            return apology("Please enter in a postiive integer", 403)

        total_price = int(shares) * share_price

        new_cash = balance - total_price

        if (new_cash < 0):
            return apology("You don't have enough money to do this")

        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash, session["user_id"])

        if len(db.execute("SELECT id FROM stonks WHERE user_id = ? AND symbol = ?", session["user_id"], lookup(buy)["symbol"])) == 0:
            db.execute("INSERT INTO stonks (symbol, user_id, shares) VALUES (?, ?, ?)", lookup(buy)["symbol"], session["user_id"], shares)

        else:
            db.execute("UPDATE stonks SET shares = shares + ? WHERE user_id = ? AND symbol = ?", shares, session["user_id"], lookup(buy)["symbol"])

        # update database
        db.execute("INSERT INTO transactions VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)", lookup(buy)["symbol"], lookup(buy)["price"], shares, session["user_id"])

        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = ? ORDER BY time DESC", session["user_id"])
    return render_template("history.html", transactions = transactions)

@app.route("/inject", methods=["GET", "POST"])
@login_required
def inject():
    if request.method == "POST":
        if not request.form.get("inject"):
            return apology("Provide money", 403)

        injection = request.form.get("inject")
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", injection, session["user_id"])

        transactions = db.execute("SELECT * FROM transactions WHERE user_id = ? ORDER BY time DESC", session["user_id"])
        return redirect("/")

    else:
        return render_template("inject.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "POST":
        # receives quote
        quote = request.form.get("quote")

        # checks if this is a real quote
        if (lookup(quote) is None):
            return apology("Please enter in a valid stock abbreviation", 403)

        else:
            stock = lookup(quote)
            return render_template("quoted.html", entries = stock)

    else:
        return render_template("quote.html")
    """Get stock quote."""
    return apology("TODO")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # username = request.form.get("username")

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Add username and password to database
        if (password != confirmation):
            return apology("Passwords must match", 403)


        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", request.form.get("username"), generate_password_hash(password))

        return render_template("login.html")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")



@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "POST":
        # receives quote
        sell = request.form.get("symbol")

        # checks if this is a real quote
        if (lookup(sell) is None):
            return apology("Please enter in a valid stock abbreviation", 403)

        shares = request.form.get("shares")

        stonks = db.execute("SELECT * FROM stonks WHERE user_id = ? AND symbol = ?", session["user_id"], lookup(sell)["symbol"])

        if not shares.isdigit() or int(shares) > stonks[0]["shares"]:
            return apology("Choose a positive integer less than or equal to the number of shares you own", 403)


        share_price = lookup(sell)["price"]

        balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

        total_price = int(shares) * share_price

        new_cash = balance + total_price

        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash, session["user_id"])

        db.execute("UPDATE stonks SET shares = shares - ? WHERE user_id = ? AND symbol = ?", shares, session["user_id"], lookup(sell)["symbol"])

        if db.execute("SELECT * FROM stonks WHERE user_id = ? AND symbol = ?", session["user_id"], lookup(sell)["symbol"])[0]["shares"] == 0:
            db.execute("DELETE FROM stonks WHERE user_id = ? AND symbol = ?", session["user_id"], lookup(sell)["symbol"])

        # update database
        db.execute("INSERT INTO transactions VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)", lookup(sell)["symbol"], lookup(sell)["price"], -int(shares), session["user_id"])

        return redirect("/")

    else:
        stonks = db.execute("SELECT * FROM stonks WHERE user_id = ?", session["user_id"])
        return render_template("sell.html", stonks = stonks)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
