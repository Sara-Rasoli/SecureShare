import os
import sqlite3
import uuid
import json
import hashlib

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    send_from_directory
)

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


# =========================================================
# FLASK APPLICATION
# =========================================================

app = Flask(__name__)

app.secret_key = "development-secret-key-change-later"


# =========================================================
# CONFIGURATION
# =========================================================

DATABASE = "database.db"

UPLOAD_FOLDER = "uploads"

ENCRYPTED_FOLDER = "encrypted_files"

KEY_FOLDER = "keys"

ALLOWED_EXTENSIONS = {
    "pdf",
    "txt",
    "doc",
    "docx",
    "jpg",
    "jpeg",
    "png"
}


# =========================================================
# CREATE REQUIRED FOLDERS
# =========================================================

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)

os.makedirs(KEY_FOLDER, exist_ok=True)


# =========================================================
# DATABASE
# =========================================================

def get_db_connection():
    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def initialize_database():
    connection = get_db_connection()

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
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
            FOREIGN KEY (uploaded_by)
                REFERENCES users(id)
                ON DELETE CASCADE
        )
        """
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS document_shares (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id INTEGER NOT NULL,
            shared_with INTEGER NOT NULL,
            shared_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(document_id, shared_with),
            FOREIGN KEY (document_id)
                REFERENCES documents(id)
                ON DELETE CASCADE,
            FOREIGN KEY (shared_with)
                REFERENCES users(id)
                ON DELETE CASCADE
        )
        """
    )

    connection.commit()

    connection.close()


# =========================================================
# RSA KEY MANAGEMENT
# =========================================================

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

    if (
        os.path.exists(private_key_path)
        and os.path.exists(public_key_path)
    ):
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    private_key_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_data = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(private_key_path, "wb") as private_file:
        private_file.write(private_key_data)

    with open(public_key_path, "wb") as public_file:
        public_file.write(public_key_data)


def generate_missing_user_keys():
    """
    Generate RSA keys for existing users who do not have them.
    """

    connection = get_db_connection()

    users = connection.execute(
        """
        SELECT id
        FROM users
        """
    ).fetchall()

    connection.close()

    for user in users:
        generate_user_rsa_keys(user["id"])


def load_user_public_key(user_id):
    """
    Load a user's RSA public key.
    """

    public_key_path = os.path.join(
        KEY_FOLDER,
        f"user_{user_id}_public.pem"
    )

    if not os.path.exists(public_key_path):
        generate_user_rsa_keys(user_id)

    with open(public_key_path, "rb") as public_file:
        return serialization.load_pem_public_key(
            public_file.read()
        )


def load_user_private_key(user_id):
    """
    Load a user's RSA private key.
    """

    private_key_path = os.path.join(
        KEY_FOLDER,
        f"user_{user_id}_private.pem"
    )

    if not os.path.exists(private_key_path):
        generate_user_rsa_keys(user_id)

    with open(private_key_path, "rb") as private_file:
        return serialization.load_pem_private_key(
            private_file.read(),
            password=None
        )


# =========================================================
# SHA-256 HASHING
# =========================================================

def calculate_sha256(file_data):
    """
    Calculate SHA-256 hash of data.
    """

    return hashlib.sha256(file_data).hexdigest()


# =========================================================
# AES-256-GCM ENCRYPTION
# =========================================================

def encrypt_file_with_aes(file_data):
    """
    Encrypt file data using AES-256-GCM.

    Returns:
        encrypted_data
        aes_key
        nonce
    """

    aes_key = AESGCM.generate_key(
        bit_length=256
    )

    nonce = os.urandom(12)

    aes = AESGCM(aes_key)

    encrypted_data = aes.encrypt(
        nonce,
        file_data,
        None
    )

    return encrypted_data, aes_key, nonce


def decrypt_file_with_aes(
    encrypted_data,
    aes_key,
    nonce
):
    """
    Decrypt AES-256-GCM encrypted data.
    """

    aes = AESGCM(aes_key)

    decrypted_data = aes.decrypt(
        nonce,
        encrypted_data,
        None
    )

    return decrypted_data


# =========================================================
# RSA AES-KEY WRAPPING
# =========================================================

def encrypt_aes_key_with_rsa(
    aes_key,
    recipient_user_id
):
    """
    Encrypt the AES key using a recipient's RSA public key.
    """

    recipient_public_key = load_user_public_key(
        recipient_user_id
    )

    encrypted_aes_key = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_aes_key


def decrypt_aes_key_with_rsa(
    encrypted_aes_key,
    user_id
):
    """
    Decrypt the AES key using the user's RSA private key.
    """

    private_key = load_user_private_key(
        user_id
    )

    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return aes_key


# =========================================================
# DIGITAL SIGNATURES
# =========================================================

def create_file_signature(
    file_hash,
    user_id
):
    """
    Create an RSA-PSS digital signature
    for the SHA-256 hash of the original file.
    """

    private_key = load_user_private_key(
        user_id
    )

    signature = private_key.sign(
        file_hash.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(
                hashes.SHA256()
            ),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


def verify_file_signature(
    file_hash,
    signature,
    owner_user_id
):
    """
    Verify the digital signature using
    the document owner's RSA public key.
    """

    public_key = load_user_public_key(
        owner_user_id
    )

    try:
        public_key.verify(
            signature,
            file_hash.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(
                    hashes.SHA256()
                ),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True

    except Exception:
        return False


# =========================================================
# ENCRYPTED PACKAGE HELPERS
# =========================================================

def load_encrypted_package(package_path):
    """
    Load an encrypted SecureShare package.
    """

    with open(
        package_path,
        "r",
        encoding="utf-8"
    ) as package_file:

        return json.load(package_file)


def save_encrypted_package(
    package_path,
    package
):
    """
    Save an encrypted SecureShare package.
    """

    with open(
        package_path,
        "w",
        encoding="utf-8"
    ) as package_file:

        json.dump(
            package,
            package_file,
            indent=4
        )


def create_encrypted_key_map(
    aes_key,
    user_ids
):
    """
    Create RSA-wrapped AES keys for multiple users.

    Each user's RSA public key encrypts
    the same AES key.
    """

    encrypted_keys = {}

    for user_id in user_ids:

        encrypted_key = encrypt_aes_key_with_rsa(
            aes_key,
            user_id
        )

        encrypted_keys[str(user_id)] = (
            encrypted_key.hex()
        )

    return encrypted_keys


def get_aes_key_from_package(
    package,
    user_id
):
    """
    Recover the AES key from the encrypted package
    using the current user's RSA private key.

    Supports:

    1. New packages with encrypted_aes_keys
    2. Older packages with encrypted_aes_key
    """

    # New package format

    if "encrypted_aes_keys" in package:

        encrypted_keys = package[
            "encrypted_aes_keys"
        ]

        user_key = encrypted_keys.get(
            str(user_id)
        )

        if not user_key:
            raise ValueError(
                "No encrypted AES key is available "
                "for this user."
            )

        encrypted_aes_key = bytes.fromhex(
            user_key
        )

        return decrypt_aes_key_with_rsa(
            encrypted_aes_key,
            user_id
        )

    # Backward compatibility with old package format

    if "encrypted_aes_key" in package:

        encrypted_aes_key = bytes.fromhex(
            package["encrypted_aes_key"]
        )

        return decrypt_aes_key_with_rsa(
            encrypted_aes_key,
            user_id
        )

    raise ValueError(
        "Encrypted AES key not found in package."
    )


# =========================================================
# HELPER FUNCTIONS
# =========================================================

def allowed_file(filename):
    """
    Check whether a file extension is allowed.
    """

    return (
        "." in filename
        and filename.rsplit(
            ".",
            1
        )[1].lower()
        in ALLOWED_EXTENSIONS
    )


def user_can_access_document(
    document_id,
    user_id
):
    """
    Check whether a user owns a document
    or has permission to access it.
    """

    connection = get_db_connection()

    document = connection.execute(
        """
        SELECT id
        FROM documents
        WHERE id = ?
        AND uploaded_by = ?
        """,
        (
            document_id,
            user_id
        )
    ).fetchone()

    if document:
        connection.close()
        return True

    shared_document = connection.execute(
        """
        SELECT id
        FROM document_shares
        WHERE document_id = ?
        AND shared_with = ?
        """,
        (
            document_id,
            user_id
        )
    ).fetchone()

    connection.close()

    return shared_document is not None


# =========================================================
# HOME
# =========================================================

@app.route("/")
def index():

    return render_template(
        "index.html"
    )


# =========================================================
# REGISTER
# =========================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if request.method == "POST":

        username = request.form[
            "username"
        ].strip()

        email = request.form[
            "email"
        ].strip().lower()

        password = request.form[
            "password"
        ]

        if not username or not email or not password:

            flash(
                "All fields are required.",
                "error"
            )

            return redirect(
                url_for("register")
            )

        password_hash = generate_password_hash(
            password
        )

        connection = get_db_connection()

        try:

            connection.execute(
                """
                INSERT INTO users (
                    username,
                    email,
                    password_hash
                )
                VALUES (?, ?, ?)
                """,
                (
                    username,
                    email,
                    password_hash
                )
            )

            connection.commit()

        except sqlite3.IntegrityError:

            connection.close()

            flash(
                "An account with this email already exists.",
                "error"
            )

            return redirect(
                url_for("register")
            )

        new_user = connection.execute(
            """
            SELECT id
            FROM users
            WHERE email = ?
            """,
            (
                email,
            )
        ).fetchone()

        connection.close()

        if new_user:

            generate_user_rsa_keys(
                new_user["id"]
            )

        flash(
            "Registration successful. You can now log in.",
            "success"
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "register.html"
    )


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        email = request.form[
            "email"
        ].strip().lower()

        password = request.form[
            "password"
        ]

        connection = get_db_connection()

        user = connection.execute(
            """
            SELECT *
            FROM users
            WHERE email = ?
            """,
            (
                email,
            )
        ).fetchone()

        connection.close()

        if user and check_password_hash(
            user["password_hash"],
            password
        ):

            session["user_id"] = user["id"]

            session["username"] = user["username"]

            generate_user_rsa_keys(
                user["id"]
            )

            flash(
                "Login successful.",
                "success"
            )

            return redirect(
                url_for("dashboard")
            )

        flash(
            "Invalid email or password.",
            "error"
        )

    return render_template(
        "login.html"
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(
        url_for("index")
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:

        flash(
            "Please log in first.",
            "error"
        )

        return redirect(
            url_for("login")
        )

    user_id = session["user_id"]

    connection = get_db_connection()

    owned_documents = connection.execute(
        """
        SELECT *
        FROM documents
        WHERE uploaded_by = ?
        ORDER BY upload_date DESC
        """,
        (
            user_id,
        )
    ).fetchall()

    shared_documents = connection.execute(
        """
        SELECT
            documents.id,
            documents.filename,
            documents.upload_date,
            users.username AS owner_username
        FROM document_shares
        JOIN documents
            ON document_shares.document_id = documents.id
        JOIN users
            ON documents.uploaded_by = users.id
        WHERE document_shares.shared_with = ?
        ORDER BY document_shares.shared_at DESC
        """,
        (
            user_id,
        )
    ).fetchall()

    users = connection.execute(
        """
        SELECT id, username, email
        FROM users
        WHERE id != ?
        ORDER BY username
        """,
        (
            user_id,
        )
    ).fetchall()

    connection.close()

    return render_template(
        "dashboard.html",
        owned_documents=owned_documents,
        shared_documents=shared_documents,
        users=users
    )


# =========================================================
# UPLOAD + HYBRID ENCRYPTION
# =========================================================

@app.route(
    "/upload",
    methods=["POST"]
)
def upload():

    if "user_id" not in session:

        flash(
            "Please log in first.",
            "error"
        )

        return redirect(
            url_for("login")
        )

    if "file" not in request.files:

        flash(
            "No file was selected.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    file = request.files["file"]

    if file.filename == "":

        flash(
            "No file was selected.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    if not allowed_file(file.filename):

        flash(
            "This file type is not allowed.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    user_id = session["user_id"]

    original_filename = secure_filename(
        file.filename
    )

    # Step 1: Read original file

    file_data = file.read()

    if not file_data:

        flash(
            "The selected file is empty.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    # Step 2: Calculate SHA-256

    file_hash = calculate_sha256(
        file_data
    )

    # Step 3: AES-256-GCM encryption

    encrypted_data, aes_key, nonce = (
        encrypt_file_with_aes(
            file_data
        )
    )

    # Step 4: RSA-wrap AES key for owner

    encrypted_aes_keys = (
        create_encrypted_key_map(
            aes_key,
            [user_id]
        )
    )

    # Step 5: Create digital signature

    signature = create_file_signature(
        file_hash,
        user_id
    )

    # Step 6: Generate package filename

    document_id = str(
        uuid.uuid4()
    )

    package_filename = (
        f"{document_id}.secure"
    )

    package_path = os.path.join(
        ENCRYPTED_FOLDER,
        package_filename
    )

    # Step 7: Build encrypted package

    package = {
        "version": 2,
        "original_filename": original_filename,
        "encrypted_aes_keys": encrypted_aes_keys,
        "nonce": nonce.hex(),
        "sha256": file_hash,
        "signature": signature.hex(),
        "signature_algorithm": "RSA-PSS-SHA256",
        "encryption_algorithm": "AES-256-GCM",
        "key_encryption_algorithm": "RSA-OAEP-SHA256",
        "encrypted_data": encrypted_data.hex()
    }

    # Step 8: Store encrypted package

    save_encrypted_package(
        package_path,
        package
    )

    # Step 9: Store document metadata

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
            package_filename,
            user_id
        )
    )

    connection.commit()

    connection.close()

    flash(
        "File uploaded, encrypted and digitally signed successfully.",
        "success"
    )

    return redirect(
        url_for("dashboard")
    )


# =========================================================
# DOWNLOAD / DECRYPT / VERIFY
# =========================================================

@app.route(
    "/download/<int:document_id>"
)
def download(document_id):

    if "user_id" not in session:

        flash(
            "Please log in first.",
            "error"
        )

        return redirect(
            url_for("login")
        )

    user_id = session["user_id"]

    # Step 1: Check application-level access

    if not user_can_access_document(
        document_id,
        user_id
    ):

        flash(
            "You do not have permission to access this file.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    connection = get_db_connection()

    document = connection.execute(
        """
        SELECT *
        FROM documents
        WHERE id = ?
        """,
        (
            document_id,
        )
    ).fetchone()

    connection.close()

    if not document:

        flash(
            "Document not found.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    package_path = os.path.join(
        ENCRYPTED_FOLDER,
        document["stored_filename"]
    )

    if not os.path.exists(package_path):

        flash(
            "Encrypted file package not found.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    try:

        # Step 2: Read encrypted package

        package = load_encrypted_package(
            package_path
        )

        encrypted_data = bytes.fromhex(
            package["encrypted_data"]
        )

        nonce = bytes.fromhex(
            package["nonce"]
        )

        original_hash = package[
            "sha256"
        ]

        original_filename = package[
            "original_filename"
        ]

        # Step 3: Recover AES key

        aes_key = get_aes_key_from_package(
            package,
            user_id
        )

        # Step 4: AES-256-GCM decryption

        decrypted_data = decrypt_file_with_aes(
            encrypted_data,
            aes_key,
            nonce
        )

        # Step 5: SHA-256 integrity verification

        decrypted_hash = calculate_sha256(
            decrypted_data
        )

        if decrypted_hash != original_hash:

            flash(
                "File integrity verification failed. "
                "The file may have been modified.",
                "error"
            )

            return redirect(
                url_for("dashboard")
            )

        # Step 6: Find document owner

        connection = get_db_connection()

        owner = connection.execute(
            """
            SELECT uploaded_by
            FROM documents
            WHERE id = ?
            """,
            (
                document_id,
            )
        ).fetchone()

        connection.close()

        if not owner:

            flash(
                "Document owner could not be found.",
                "error"
            )

            return redirect(
                url_for("dashboard")
            )

        owner_user_id = owner[
            "uploaded_by"
        ]

        # Step 7: Verify digital signature

        if "signature" in package:

            signature = bytes.fromhex(
                package["signature"]
            )

            signature_valid = (
                verify_file_signature(
                    decrypted_hash,
                    signature,
                    owner_user_id
                )
            )

            if not signature_valid:

                flash(
                    "Digital signature verification failed. "
                    "The file may not be authentic.",
                    "error"
                )

                return redirect(
                    url_for("dashboard")
                )

        # Step 8: Create temporary decrypted file

        temporary_filename = (
            f"decrypted_{uuid.uuid4()}_"
            f"{original_filename}"
        )

        temporary_path = os.path.join(
            UPLOAD_FOLDER,
            temporary_filename
        )

        with open(
            temporary_path,
            "wb"
        ) as decrypted_file:

            decrypted_file.write(
                decrypted_data
            )

        # Step 9: Send decrypted file

        response = send_from_directory(
            UPLOAD_FOLDER,
            temporary_filename,
            as_attachment=True,
            download_name=original_filename
        )

        # Step 10: Remove temporary plaintext

        @response.call_on_close
        def remove_temporary_file():

            try:

                if os.path.exists(
                    temporary_path
                ):

                    os.remove(
                        temporary_path
                    )

            except OSError:

                pass

        return response

    except Exception:

        flash(
            "Unable to decrypt the file. "
            "The encrypted package may be damaged, "
            "the encryption key may be unavailable, "
            "or cryptographic verification may have failed.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )


# =========================================================
# SHARE DOCUMENT
# =========================================================

@app.route(
    "/share/<int:document_id>",
    methods=["POST"]
)
def share_document(document_id):

    if "user_id" not in session:

        flash(
            "Please log in first.",
            "error"
        )

        return redirect(
            url_for("login")
        )

    owner_id = session["user_id"]

    shared_with = request.form.get(
        "shared_with"
    )

    if not shared_with:

        flash(
            "Please select a user.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    try:

        shared_with = int(
            shared_with
        )

    except ValueError:

        flash(
            "Invalid recipient.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    connection = get_db_connection()

    # Step 1: Check document ownership

    document = connection.execute(
        """
        SELECT *
        FROM documents
        WHERE id = ?
        AND uploaded_by = ?
        """,
        (
            document_id,
            owner_id
        )
    ).fetchone()

    if not document:

        connection.close()

        flash(
            "You can only share your own documents.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    # Step 2: Prevent self-sharing

    if shared_with == owner_id:

        connection.close()

        flash(
            "You cannot share a document with yourself.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    # Step 3: Check recipient

    recipient = connection.execute(
        """
        SELECT id
        FROM users
        WHERE id = ?
        """,
        (
            shared_with,
        )
    ).fetchone()

    if not recipient:

        connection.close()

        flash(
            "Selected user does not exist.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    # Step 4: Check whether already shared

    existing_share = connection.execute(
        """
        SELECT id
        FROM document_shares
        WHERE document_id = ?
        AND shared_with = ?
        """,
        (
            document_id,
            shared_with
        )
    ).fetchone()

    if existing_share:

        connection.close()

        flash(
            "This document is already shared with that user.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    package_path = os.path.join(
        ENCRYPTED_FOLDER,
        document["stored_filename"]
    )

    if not os.path.exists(package_path):

        connection.close()

        flash(
            "Encrypted file package not found.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    try:

        # Step 5: Load encrypted package

        package = load_encrypted_package(
            package_path
        )

        # Step 6: Recover AES key using owner private key

        aes_key = get_aes_key_from_package(
            package,
            owner_id
        )

        # Step 7: Make sure new key-map format exists

        if "encrypted_aes_keys" not in package:

            package["encrypted_aes_keys"] = {}

            old_encrypted_key = package.get(
                "encrypted_aes_key"
            )

            if old_encrypted_key:

                package["encrypted_aes_keys"][
                    str(owner_id)
                ] = old_encrypted_key

        # Step 8: RSA-wrap AES key for recipient

        encrypted_recipient_key = (
            encrypt_aes_key_with_rsa(
                aes_key,
                shared_with
            )
        )

        package["encrypted_aes_keys"][
            str(shared_with)
        ] = encrypted_recipient_key.hex()

        # Step 9: Upgrade old package if necessary

        package["version"] = 2

        if "signature" not in package:

            file_hash = package.get(
                "sha256"
            )

            if file_hash:

                package["signature"] = (
                    create_file_signature(
                        file_hash,
                        owner_id
                    ).hex()
                )

                package[
                    "signature_algorithm"
                ] = "RSA-PSS-SHA256"

        # Step 10: Save updated package

        save_encrypted_package(
            package_path,
            package
        )

        # Step 11: Store database permission

        connection.execute(
            """
            INSERT INTO document_shares (
                document_id,
                shared_with
            )
            VALUES (?, ?)
            """,
            (
                document_id,
                shared_with
            )
        )

        connection.commit()

        flash(
            "Document encrypted key successfully shared with the selected user.",
            "success"
        )

    except Exception:

        connection.rollback()

        flash(
            "Unable to share the document securely.",
            "error"
        )

    finally:

        connection.close()

    return redirect(
        url_for("dashboard")
    )


# =========================================================
# UNSHARE DOCUMENT
# =========================================================

@app.route(
    "/unshare/<int:document_id>/<int:user_id>",
    methods=["POST"]
)
def unshare_document(
    document_id,
    user_id
):

    if "user_id" not in session:

        flash(
            "Please log in first.",
            "error"
        )

        return redirect(
            url_for("login")
        )

    owner_id = session["user_id"]

    connection = get_db_connection()

    # Step 1: Check ownership

    document = connection.execute(
        """
        SELECT *
        FROM documents
        WHERE id = ?
        AND uploaded_by = ?
        """,
        (
            document_id,
            owner_id
        )
    ).fetchone()

    if not document:

        connection.close()

        flash(
            "You can only manage sharing for your own documents.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    # Step 2: Remove database permission

    connection.execute(
        """
        DELETE FROM document_shares
        WHERE document_id = ?
        AND shared_with = ?
        """,
        (
            document_id,
            user_id
        )
    )

    connection.commit()

    connection.close()

    # Step 3: Remove recipient's encrypted AES key

    package_path = os.path.join(
        ENCRYPTED_FOLDER,
        document["stored_filename"]
    )

    try:

        if os.path.exists(package_path):

            package = load_encrypted_package(
                package_path
            )

            if "encrypted_aes_keys" in package:

                package[
                    "encrypted_aes_keys"
                ].pop(
                    str(user_id),
                    None
                )

                save_encrypted_package(
                    package_path,
                    package
                )

    except Exception:

        flash(
            "Sharing permission was removed, "
            "but the encrypted key could not be updated.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    flash(
        "Document sharing permission removed.",
        "success"
    )

    return redirect(
        url_for("dashboard")
    )


# =========================================================
# DELETE DOCUMENT
# =========================================================

@app.route(
    "/delete/<int:document_id>",
    methods=["POST"]
)
def delete_document(document_id):

    if "user_id" not in session:

        flash(
            "Please log in first.",
            "error"
        )

        return redirect(
            url_for("login")
        )

    user_id = session["user_id"]

    connection = get_db_connection()

    document = connection.execute(
        """
        SELECT *
        FROM documents
        WHERE id = ?
        AND uploaded_by = ?
        """,
        (
            document_id,
            user_id
        )
    ).fetchone()

    if not document:

        connection.close()

        flash(
            "You can only delete your own documents.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    # document_shares are removed automatically
    # because of ON DELETE CASCADE.

    connection.execute(
        """
        DELETE FROM documents
        WHERE id = ?
        """,
        (
            document_id,
        )
    )

    connection.commit()

    connection.close()

    package_path = os.path.join(
        ENCRYPTED_FOLDER,
        document["stored_filename"]
    )

    if os.path.exists(package_path):

        os.remove(
            package_path
        )

    flash(
        "Document deleted successfully.",
        "success"
    )

    return redirect(
        url_for("dashboard")
    )


# =========================================================
# APPLICATION START
# =========================================================

if __name__ == "__main__":

    initialize_database()

    generate_missing_user_keys()

    app.run(
        debug=True
    )