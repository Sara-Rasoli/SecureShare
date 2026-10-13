# 🔐 SecureShare — Hybrid Cryptographic File-Sharing System

SecureShare is a secure, web-based file-sharing application that combines symmetric and asymmetric cryptography to protect files, verify data integrity, authenticate digital signatures, and manage access between registered users.

The system uses AES-256-GCM for file encryption and RSA-2048 with RSA-OAEP-SHA256 to protect AES encryption keys. It also incorporates SHA-256 hashing and RSA-PSS digital signatures to support file integrity verification and authenticity.

## ✨ Key Features

- 🔒 **AES-256-GCM Encryption** — Encrypts files using authenticated symmetric encryption.
- 🔑 **RSA-2048 Key Management** — Generates RSA key pairs and protects AES encryption keys using RSA-OAEP-SHA256.
- 🛡️ **Integrity Verification** — Uses SHA-256 hashing to verify file integrity.
- ✍️ **Digital Signatures** — Implements RSA-PSS-SHA256 for authenticity verification.
- 👥 **Secure File Sharing** — Supports file sharing between registered users.
- 🚫 **Access Control and Revocation** — Restricts unauthorized access and supports revoking file access.
- 📦 **Encrypted File Packages** — Packages encrypted files into `.secure` files for storage and sharing.

## 🛠️ Tech Stack

| Category | Technologies |
|---|---|
| Programming Language | Python |
| Web Framework | Flask |
| Database | SQLite |
| Cryptography | Python Cryptography Library |
| Frontend | HTML, CSS |
| Data Format | JSON |
| Version Control | Git, GitHub |

## 🔐 Cryptographic Architecture

| Security Purpose | Algorithm |
|---|---|
| File Encryption | AES-256-GCM |
| Encryption Key Protection | RSA-2048 with RSA-OAEP-SHA256 |
| Integrity Verification | SHA-256 |
| Digital Signatures | RSA-PSS-SHA256 |

## 🎯 Project Objectives

- Apply hybrid cryptography to secure file storage and sharing.
- Protect encryption keys using asymmetric cryptography.
- Support file integrity verification and digital signature validation.
- Implement user-based access control and file-sharing permissions.
- Explore practical approaches to web application security.

## 📚 Technical Highlights

- Implementation of symmetric and asymmetric cryptographic techniques.
- Secure file encryption and encryption-key protection.
- Cryptographic hashing and digital signature verification.
- User authentication and authorization.
- Secure file processing and encrypted package handling.
- Backend development using Python and Flask.

## 🚀 Future Improvements

- Implement multi-factor authentication.
- Enhance encryption-key lifecycle management and secure key storage.
- Introduce comprehensive automated security testing.
- Improve the user interface and file-sharing experience.
- Expand security auditing and activity logging.

## 👩‍💻 Author

**Sara Rasoli**
Computer Science Student | Aspiring Cybersecurity & Software Development Professional

- **Portfolio Interests:** Cybersecurity, Applied Cryptography, Python Development, and Web Application Security

