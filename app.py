import os
import sqlite3

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash
)

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


# --------------------------------------------------
# APPLICATION CONFIGURATION
# --------------------------------------------------

app = Flask(__name__)

# This secret key is used to protect Flask sessions.
# We will move it into an environment variable later.
app.secret_key = "development-secret-key-change-later"

# Database file
DATABASE = "database.db"

# Folder for uploaded files
UPLOAD_FOLDER = "uploads"

# Allowed file extensions for the first version
ALLOWED_EXTENSIONS = {
    "pdf",
    "txt",
    "doc",
    "docx",
    "jpg",
    "jpeg",
    "png"
}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# --------------------------------------------------
# FOLDER PREPARATION
# --------------------------------------------------

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs("encrypted_files", exist_ok=True)


# --------------------------------------------------
# DATABASE FUNCTIONS
# --------------------------------------------------

def get_db_connection():
    """
    Creates a connection to the SQLite database.
    """

    connection = sqlite3.connect(DATABASE)

    # Allows us to access columns by their names.
    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():
    """
    Creates the users and documents tables
    if they do not already exist.
    """

    connection = get_db_connection()

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
        """
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            uploaded_by INTEGER NOT NULL,
            upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (uploaded_by) REFERENCES users (id)
        )
        """
    )

    connection.commit()
    connection.close()


# --------------------------------------------------
# FILE VALIDATION
# --------------------------------------------------

def allowed_file(filename):
    """
    Checks whether the uploaded file has an allowed extension.
    """

    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


# --------------------------------------------------
# HOME PAGE
# --------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


# --------------------------------------------------
# REGISTRATION
# --------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Check for empty fields
        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for("register"))

        # Check password confirmation
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("register"))

        # Check minimum password length
        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "danger")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)

        connection = get_db_connection()

        try:
            connection.execute(
                """
                INSERT INTO users (username, email, password_hash)
                VALUES (?, ?, ?)
                """,
                (username, email, password_hash)
            )

            connection.commit()

            flash("Registration successful. You can now log in.", "success")

        except sqlite3.IntegrityError:
            flash("Username or email already exists.", "danger")

        finally:
            connection.close()

        return redirect(url_for("login"))

    return render_template("register.html")


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        connection = get_db_connection()

        user = connection.execute(
            """
            SELECT * FROM users
            WHERE email = ?
            """,
            (email,)
        ).fetchone()

        connection.close()

        if user and check_password_hash(user["password_hash"], password):

            session["user_id"] = user["id"]
            session["username"] = user["username"]

            flash("Login successful.", "success")

            return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "danger")

        return redirect(url_for("login"))

    return render_template("login.html")


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout")
def logout():

    session.clear()

    flash("You have been logged out.", "success")

    return redirect(url_for("index"))


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        flash("Please log in first.", "danger")
        return redirect(url_for("login"))

    connection = get_db_connection()

    documents = connection.execute(
        """
        SELECT documents.*, users.username
        FROM documents
        JOIN users ON documents.uploaded_by = users.id
        ORDER BY documents.upload_date DESC
        """
    ).fetchall()

    connection.close()

    return render_template(
        "dashboard.html",
        documents=documents
    )


# --------------------------------------------------
# DOCUMENT UPLOAD
# --------------------------------------------------

@app.route("/upload", methods=["POST"])
def upload_file():

    if "user_id" not in session:
        flash("Please log in first.", "danger")
        return redirect(url_for("login"))

    if "file" not in request.files:
        flash("No file was selected.", "danger")
        return redirect(url_for("dashboard"))

    file = request.files["file"]

    if file.filename == "":
        flash("No file was selected.", "danger")
        return redirect(url_for("dashboard"))

    if not allowed_file(file.filename):
        flash("This file type is not allowed.", "danger")
        return redirect(url_for("dashboard"))

    original_filename = secure_filename(file.filename)

    # Add the user ID to avoid simple filename conflicts.
    stored_filename = f"{session['user_id']}_{original_filename}"

    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        stored_filename
    )

    file.save(file_path)

    connection = get_db_connection()

    connection.execute(
        """
        INSERT INTO documents (
            filename,
            stored_filename,
            uploaded_by
        )
        VALUES (?, ?, ?)
        """,
        (
            original_filename,
            stored_filename,
            session["user_id"]
        )
    )

    connection.commit()
    connection.close()

    flash("File uploaded successfully.", "success")

    return redirect(url_for("dashboard"))


# --------------------------------------------------
# APPLICATION START
# --------------------------------------------------

if __name__ == "__main__":

    initialize_database()

    app.run(
        debug=True
    )