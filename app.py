import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")
db.execute(
    "CREATE TABLE IF NOT EXISTS purchases(user_id INTEGER, stock TEXT NOT NULL, price REAL NOT NULL, number_of_shares INTEGER NOT NULL, FOREIGN kEY(user_id) REFERENCES users(id))"
)
db.execute(
    "CREATE TABLE IF NOT EXISTS history(user_id INTEGER, stock TEXT NOT NULL, price REAL NOT NULL, number_of_shares INTEGER NOT NULL,date DATETIME, FOREIGN kEY(user_id) REFERENCES users(id))"
)


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    purchases = db.execute(
        "SELECT stock, SUM(number_of_shares) AS shares, price, price * SUM(number_of_shares) AS total_holding_value FROM purchases JOIN users ON users.id=purchases.user_id WHERE user_id=? GROUP BY stock",
        session["user_id"],
    )
    row = db.execute("SELECT cash FROM users WHERE id=?;", session["user_id"])
    cash_left = row[0]["cash"]
    sum = db.execute(
        "SELECT SUM(price * number_of_shares) AS sum FROM purchases WHERE user_id =? GROUP BY user_id",
        session["user_id"],
    )
    if len(sum) >= 1:
        sum_total = sum[0]["sum"] + cash_left
        return render_template(
            "index.html", purchases=purchases, cash_left=cash_left, sum_total=sum_total
        )
    else:
        sum_total = cash_left
        return render_template("index.html", cash_left=cash_left, sum_total=sum_total)
    # return apology("TODO")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        if not request.form.get("symbol"):
            return apology("Input necessary field(s)")
        elif not request.form.get("shares"):
            return apology("Input necessary field(s)")
        try:
            shares = int(shares)
            if shares <= 0:
                return apology("Must be a positive integer")
        except ValueError:
            return apology("Input must be an integer")
        result = lookup(symbol)
        if result == None:
            return apology("Unknown stock symbol")
        total = result["price"] * shares
        row = db.execute("SELECT cash FROM users WHERE id=?;", session["user_id"])
        cash = row[0]["cash"]
        if cash < total:
            return apology("Not enough money")
        check = db.execute(
            "SELECT * FROM purchases WHERE user_id=? AND stock=?",
            session["user_id"],
            symbol,
        )
        if len(check) == 1:
            db.execute(
                "UPDATE purchases SET number_of_shares=? WHERE user_id=? AND stock=?",
                check[0]["number_of_shares"] + shares,
                session["user_id"],
                symbol,
            )
        else:
            db.execute(
                "INSERT INTO purchases(user_id, stock, price, number_of_shares) VALUES(?, ?, ?, ?)",
                session["user_id"],
                symbol,
                result["price"],
                shares,
            )
        db.execute(
            "UPDATE users SET cash = ? WHERE id = ?", cash - total, session["user_id"]
        )
        db.execute(
            "INSERT INTO history(user_id, stock, price, number_of_shares, date) VALUES(?, ?, ?, ?, DATETIME())",
            session["user_id"],
            symbol,
            result["price"],
            shares,
        )
        flash("Bought!")
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    events = db.execute("SELECT * FROM history WHERE user_id=?", session["user_id"])
    return render_template("history.html", events=events)


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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not request.form.get("symbol"):
            return apology("Enter symbol")
        result = lookup(symbol)
        if result == None:
            return apology("Unknown stock symbol")
        return render_template(
            "quoted.html", name=result["name"], price=result["price"]
        )
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not username:
            return apology("Username field necessary", 400)
        elif not password:
            return apology("password field necessary ", 400)
        elif not confirmation:
            return apology("confirmation field necessary", 400)
        elif password != confirmation:
            return apology("password and confirmation do not match", 400)
        row = db.execute("SELECT * FROM users WHERE username = ?", username)
        if len(row) != 0:
            return apology("Name taken", 400)

        # TODO: Add the user's entry into the database
        hash = generate_password_hash(password)
        check_password_hash(hash, password)

        id = db.execute(
            "INSERT INTO users(username, hash) VALUES(?, ?)", username, hash
        )
        session["user_id"] = id
        flash("Registered")

        return redirect("/")

    else:
        # TODO: Display the entries in the database on index.html

        return render_template("register.html")

    # return apology("TODO")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        if not shares:
            return apology("Shares field missing")
        shares = int(shares)
        if shares <= 0:
            return apology("Must be a positive integer")
        stock = db.execute(
            "SELECT user_id, stock, price, number_of_shares, cash, SUM(price * number_of_shares) AS total FROM purchases JOIN users ON purchases.user_id = users.id WHERE user_id = ? AND stock =? GROUP BY stock",
            session["user_id"],
            symbol,
        )
        if len(stock) != 1:
            return apology("You do not possess any share of this stock")
        if shares > stock[0]["number_of_shares"]:
            return apology("You do not possess this number of shares")
        db.execute(
            "UPDATE purchases SET number_of_shares = ? WHERE user_id = ? AND stock = ?",
            stock[0]["number_of_shares"] - shares,
            session["user_id"],
            stock[0]["stock"],
        )
        db.execute(
            "UPDATE users SET cash = ? WHERE id = ?",
            stock[0]["cash"] + stock[0]["price"] * shares,
            session["user_id"],
        )
        db.execute(
            "DELETE FROM purchases WHERE user_id =? AND number_of_shares = ?",
            session["user_id"],
            0,
        )
        db.execute(
            "INSERT INTO history(user_id, stock, price, number_of_shares, date) VALUES(?, ?, ?, ?, DATETIME())",
            session["user_id"],
            symbol,
            stock[0]["price"],
            -(shares),
        )
        flash("Sold!")
        return redirect("/")
    else:
        field = db.execute(
            "SELECT stock FROM purchases WHERE user_id=?", session["user_id"]
        )
        return render_template("sell.html", field=field)


#    return apology("TODO")
@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    """Add extra cash"""
    if request.method == "POST":
        cash = request.form.get("cash")
        if not request.form.get("cash"):
            return apology("Input necessary field(s)")
        cash = int(cash)
        extra = db.execute("SELECT cash FROM users WHERE id=?", session["user_id"])
        db.execute(
            "UPDATE users SET cash = ? WHERE id = ?",
            extra[0]["cash"] + cash,
            session["user_id"],
        )
        flash("Cash added")
        return redirect("/")
    else:
        return render_template("cash.html")
