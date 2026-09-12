import os
import sqlite3
import uuid

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    send_from_directory
)

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


app = Flask(__name__)

app.secret_key = "development-secret-key-change-later"

DATABASE = "database.db"
UPLOAD_FOLDER = "uploads"
ENCRYPTED_FOLDER = "encrypted_files"
KEY_FOLDER = "keys"

ALLOWED_EXTENSIONS = {
    "pdf", "txt", "doc", "docx", "jpg", "jpeg", "png"
}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["ENCRYPTED_FOLDER"] = ENCRYPTED_FOLDER


# Create required folders
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(KEY_FOLDER, exist_ok=True)


# ---------------------------------------------------------
# DATABASE CONNECTION
# ---------------------------------------------------------

def get_db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


# ---------------------------------------------------------
# DATABASE INITIALIZATION
# ---------------------------------------------------------

def initialize_database():
    connection = get_db_connection()

    # Users table
    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
    """)

    # Documents table
    connection.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            uploaded_by INTEGER NOT NULL,
            upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (uploaded_by) REFERENCES users (id)
        )
    """)

    # Document sharing permissions
    connection.execute("""
        CREATE TABLE IF NOT EXISTS document_shares (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id INTEGER NOT NULL,
            shared_with INTEGER NOT NULL,
            shared_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(document_id, shared_with),
            FOREIGN KEY (document_id) REFERENCES documents (id) ON DELETE CASCADE,
            FOREIGN KEY (shared_with) REFERENCES users (id) ON DELETE CASCADE
        )
    """)

    connection.commit()
    connection.close()
    
def generate_user_rsa_keys(user_id):
    """
    Generate an RSA public/private key pair for a user.
    """

    private_key_path = os.path.join(
        KEY_FOLDER,
        f"user_{user_id}_private.pem"
    )

    public_key_path = os.path.join(
        KEY_FOLDER,
        f"user_{user_id}_public.pem"
    )

    # Do not generate another pair if the user already has one.
    if (
        os.path.exists(private_key_path)
        and os.path.exists(public_key_path)
    ):
        return

    # Generate a 2048-bit RSA private key.
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    # Serialize private key
    private_key_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key
    public_key_data = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save private key
    with open(private_key_path, "wb") as private_file:
        private_file.write(private_key_data)

    # Save public key
    with open(public_key_path, "wb") as public_file:
        public_file.write(public_key_data)
        
def generate_missing_user_keys():
    """
    Generate RSA keys for existing users who do not have them.
    """

    connection = get_db_connection()

    users = connection.execute("""
        SELECT id
        FROM users
    """).fetchall()

    connection.close()

    for user in users:
        generate_user_rsa_keys(user["id"])
# ---------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------

def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def user_can_access_document(document_id, user_id):
    """
    Check whether a user owns a document
    or has been given permission to access it.
    """

    connection = get_db_connection()

    document = connection.execute("""
        SELECT *
        FROM documents
        WHERE id = ?
    """, (document_id,)).fetchone()

    if document is None:
        connection.close()
        return False

    # Owner has access
    if document["uploaded_by"] == user_id:
        connection.close()
        return True

    # Check sharing permission
    share = connection.execute("""
        SELECT *
        FROM document_shares
        WHERE document_id = ?
        AND shared_with = ?
    """, (document_id, user_id)).fetchone()

    connection.close()

    return share is not None


# ---------------------------------------------------------
# HOME
# ---------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------
# REGISTER
# ---------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash(
                "Password must contain at least 8 characters.",
                "danger"
            )
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)

        connection = get_db_connection()

        try:

            connection.execute("""
                INSERT INTO users (
                    username,
                    email,
                    password_hash
                )
                VALUES (?, ?, ?)
            """, (
                username,
                email,
                password_hash
            ))

            connection.commit()

            # Get the newly created user's ID
            new_user = connection.execute("""
                SELECT id
                FROM users
                WHERE email = ?
            """, (email,)).fetchone()

            if new_user:
                generate_user_rsa_keys(new_user["id"])

            flash(
                "Registration successful. You can now log in.",
                "success"
            )

        except sqlite3.IntegrityError:

            flash(
                "Username or email already exists.",
                "danger"
            )

        finally:

            connection.close()

        return redirect(url_for("login"))

    return render_template("register.html")


# ---------------------------------------------------------
# LOGIN
# ---------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        connection = get_db_connection()

        user = connection.execute("""
            SELECT *
            FROM users
            WHERE email = ?
        """, (email,)).fetchone()

        connection.close()

        if user and check_password_hash(
            user["password_hash"],
            password
        ):

            session["user_id"] = user["id"]
            session["username"] = user["username"]

            flash(
                "Login successful.",
                "success"
            )

            return redirect(url_for("dashboard"))

        flash(
            "Invalid email or password.",
            "danger"
        )

        return redirect(url_for("login"))

    return render_template("login.html")


# ---------------------------------------------------------
# LOGOUT
# ---------------------------------------------------------

@app.route("/logout")
def logout():

    session.clear()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(url_for("index"))


# ---------------------------------------------------------
# DASHBOARD
# ---------------------------------------------------------

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:

        flash(
            "Please log in first.",
            "danger"
        )

        return redirect(url_for("login"))

    user_id = session["user_id"]

    connection = get_db_connection()

    # Documents owned by the current user
    owned_documents = connection.execute("""
        SELECT
            documents.*,
            users.username AS owner
        FROM documents
        JOIN users
            ON documents.uploaded_by = users.id
        WHERE documents.uploaded_by = ?
        ORDER BY documents.upload_date DESC
    """, (user_id,)).fetchall()

    # Documents shared with the current user
    shared_documents = connection.execute("""
        SELECT
            documents.*,
            users.username AS owner
        FROM documents
        JOIN document_shares
            ON documents.id = document_shares.document_id
        JOIN users
            ON documents.uploaded_by = users.id
        WHERE document_shares.shared_with = ?
        ORDER BY document_shares.shared_at DESC
    """, (user_id,)).fetchall()

    # Other users for the sharing dropdown
    users = connection.execute("""
        SELECT id, username, email
        FROM users
        WHERE id != ?
        ORDER BY username
    """, (user_id,)).fetchall()

    connection.close()

    return render_template(
        "dashboard.html",
        owned_documents=owned_documents,
        shared_documents=shared_documents,
        users=users
    )


# ---------------------------------------------------------
# UPLOAD FILE
# ---------------------------------------------------------

@app.route("/upload", methods=["POST"])
def upload_file():

    if "user_id" not in session:

        flash(
            "Please log in first.",
            "danger"
        )

        return redirect(url_for("login"))

    if "file" not in request.files:

        flash(
            "No file was selected.",
            "danger"
        )

        return redirect(url_for("dashboard"))

    file = request.files["file"]

    if file.filename == "":

        flash(
            "No file was selected.",
            "danger"
        )

        return redirect(url_for("dashboard"))

    if not allowed_file(file.filename):

        flash(
            "This file type is not allowed.",
            "danger"
        )

        return redirect(url_for("dashboard"))

    original_filename = secure_filename(file.filename)

    # Generate a unique random filename.
    # The original filename is stored separately in the database.
    file_extension = ""

    if "." in original_filename:
        file_extension = "." + original_filename.rsplit(".", 1)[1].lower()

    unique_filename = f"{uuid.uuid4().hex}{file_extension}"

    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        unique_filename
    )

    file.save(file_path)

    connection = get_db_connection()

    connection.execute("""
        INSERT INTO documents (
            filename,
            stored_filename,
            uploaded_by
        )
        VALUES (?, ?, ?)
    """, (
        original_filename,
        unique_filename,
        session["user_id"]
    ))

    connection.commit()
    connection.close()

    flash(
        "File uploaded successfully.",
        "success"
    )

    return redirect(url_for("dashboard"))


# ---------------------------------------------------------
# DOWNLOAD FILE
# ---------------------------------------------------------

@app.route("/download/<int:document_id>")
def download_file(document_id):

    if "user_id" not in session:

        flash(
            "Please log in first.",
            "danger"
        )

        return redirect(url_for("login"))

    user_id = session["user_id"]

    # Security check
    if not user_can_access_document(
        document_id,
        user_id
    ):

        flash(
            "You do not have permission to access this file.",
            "danger"
        )

        return redirect(url_for("dashboard"))

    connection = get_db_connection()

    document = connection.execute("""
        SELECT *
        FROM documents
        WHERE id = ?
    """, (document_id,)).fetchone()

    connection.close()

    if document is None:

        flash(
            "File not found.",
            "danger"
        )

        return redirect(url_for("dashboard"))

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        document["stored_filename"],
        as_attachment=True,
        download_name=document["filename"]
    )


# ---------------------------------------------------------
# DELETE DOCUMENT
# ---------------------------------------------------------

@app.route("/delete/<int:document_id>", methods=["POST"])
def delete_document(document_id):

    if "user_id" not in session:

        flash(
            "Please log in first.",
            "danger"
        )

        return redirect(url_for("login"))

    user_id = session["user_id"]

    connection = get_db_connection()

    document = connection.execute("""
        SELECT *
        FROM documents
        WHERE id = ?
        AND uploaded_by = ?
    """, (
        document_id,
        user_id
    )).fetchone()

    if document is None:

        connection.close()

        flash(
            "You can only delete your own files.",
            "danger"
        )

        return redirect(url_for("dashboard"))

    # Delete sharing permissions first
    connection.execute("""
        DELETE FROM document_shares
        WHERE document_id = ?
    """, (document_id,))

    # Delete database record
    connection.execute("""
        DELETE FROM documents
        WHERE id = ?
    """, (document_id,))

    connection.commit()
    connection.close()

    # Delete physical file
    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        document["stored_filename"]
    )

    if os.path.exists(file_path):
        os.remove(file_path)

    flash(
        "File deleted successfully.",
        "success"
    )

    return redirect(url_for("dashboard"))


# ---------------------------------------------------------
# SHARE DOCUMENT
# ---------------------------------------------------------

@app.route("/share/<int:document_id>", methods=["POST"])
def share_document(document_id):

    if "user_id" not in session:

        flash(
            "Please log in first.",
            "danger"
        )

        return redirect(url_for("login"))

    user_id = session["user_id"]

    # Only the owner can share the document
    connection = get_db_connection()

    document = connection.execute("""
        SELECT *
        FROM documents
        WHERE id = ?
        AND uploaded_by = ?
    """, (
        document_id,
        user_id
    )).fetchone()

    if document is None:

        connection.close()

        flash(
            "You can only share files that you own.",
            "danger"
        )

        return redirect(url_for("dashboard"))

    recipient_id = request.form.get("recipient_id")

    if not recipient_id:

        connection.close()

        flash(
            "Please select a user.",
            "danger"
        )

        return redirect(url_for("dashboard"))

    try:
        recipient_id = int(recipient_id)
    except ValueError:

        connection.close()

        flash(
            "Invalid recipient.",
            "danger"
        )

        return redirect(url_for("dashboard"))

    # Make sure the recipient exists
    recipient = connection.execute("""
        SELECT *
        FROM users
        WHERE id = ?
    """, (recipient_id,)).fetchone()

    if recipient is None:

        connection.close()

        flash(
            "Selected user does not exist.",
            "danger"
        )

        return redirect(url_for("dashboard"))

    # Prevent sharing with yourself
    if recipient_id == user_id:

        connection.close()

        flash(
            "You already have access to your own file.",
            "danger"
        )

        return redirect(url_for("dashboard"))

    try:

        connection.execute("""
            INSERT INTO document_shares (
                document_id,
                shared_with
            )
            VALUES (?, ?)
        """, (
            document_id,
            recipient_id
        ))

        connection.commit()

        flash(
            f"File shared with {recipient['username']} successfully.",
            "success"
        )

    except sqlite3.IntegrityError:

        flash(
            "This file has already been shared with that user.",
            "danger"
        )

    finally:

        connection.close()

    return redirect(url_for("dashboard"))


# ---------------------------------------------------------
# REMOVE SHARE PERMISSION
# ---------------------------------------------------------

@app.route("/unshare/<int:document_id>/<int:user_id>", methods=["POST"])
def unshare_document(document_id, user_id):

    if "user_id" not in session:

        flash(
            "Please log in first.",
            "danger"
        )

        return redirect(url_for("login"))

    owner_id = session["user_id"]

    connection = get_db_connection()

    document = connection.execute("""
        SELECT *
        FROM documents
        WHERE id = ?
        AND uploaded_by = ?
    """, (
        document_id,
        owner_id
    )).fetchone()

    if document is None:

        connection.close()

        flash(
            "You can only manage sharing for your own files.",
            "danger"
        )

        return redirect(url_for("dashboard"))

    connection.execute("""
        DELETE FROM document_shares
        WHERE document_id = ?
        AND shared_with = ?
    """, (
        document_id,
        user_id
    ))

    connection.commit()
    connection.close()

    flash(
        "File access removed.",
        "success"
    )

    return redirect(url_for("dashboard"))


# ---------------------------------------------------------
# APPLICATION START
# ---------------------------------------------------------

if __name__ == "__main__":

    initialize_database()
    generate_missing_user_keys()
    app.run(debug=True)