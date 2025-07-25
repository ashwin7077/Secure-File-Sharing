# PKI File Sharing System

## Overview

This is a Flask-based web application that implements a Public Key Infrastructure (PKI) system for secure document sharing. The application allows users to register with auto-generated digital certificates, upload documents, digitally sign them, share documents with specific users through secure URLs, and verify document authenticity through cryptographic signatures. It's designed as a coursework project demonstrating practical implementation of cryptographic primitives including digital certificates, digital signatures, and asymmetric encryption.

## Recent Changes (2025-07-25)

- **Added Secure Document Sharing System**: Users can now share documents with specific recipients through unique, time-limited URLs
- **Implemented Share Management**: Created comprehensive share link management with expiration, download limits, and revocation
- **Enhanced Security**: Added file integrity verification before each shared download
- **Restricted Access Control**: Only document owners and specific recipients can view/access shared documents
- **Disabled Direct Downloads**: All downloads now require secure share links with proper recipient verification
- **Notification System**: Real-time notifications for sharing, downloads, and digital signatures with activity tracking
- **Cross-platform Docker Support**: Created Docker Compose configuration with Windows batch files for easy deployment
- **Database Enhancement**: Added ShareLink and Notification models for comprehensive activity tracking

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

The application follows a traditional Flask web application architecture with the following key components:

### Backend Architecture
- **Framework**: Flask with SQLAlchemy ORM for database operations
- **Authentication**: Flask-Login for session management with PKI-based user verification
- **Database**: SQLite (default) with support for PostgreSQL via environment configuration
- **Cryptography**: Custom PKI implementation using Python's `cryptography` library for RSA key generation, X.509 certificate creation, and digital signatures

### Frontend Architecture
- **Template Engine**: Jinja2 with Bootstrap 5 for responsive UI
- **Styling**: Custom CSS with dark theme support
- **Icons**: Feather Icons for consistent iconography
- **Client-side**: Minimal JavaScript for form interactions and file upload feedback

### Security Architecture
- **PKI Implementation**: RSA 2048-bit key pairs with X.509 certificates
- **Digital Signatures**: SHA256withRSA algorithm for document signing
- **File Integrity**: SHA-256 hashing for document verification
- **Session Security**: Secure session management with configurable secret keys

## Key Components

### Models (models.py)
- **User**: Stores user credentials, RSA key pairs, and X.509 certificates
- **Document**: Manages uploaded files with integrity hashes and metadata
- **DocumentSignature**: Tracks digital signatures with cryptographic verification data
- **ShareLink**: Manages secure document sharing with time limits, download tracking, and access control
- **Notification**: Real-time activity notifications for sharing, downloads, signatures, and system events

### Cryptographic Module (crypto_utils.py)
- **PKIManager**: Handles RSA key generation, certificate creation, and digital signature operations
- **Key Generation**: 2048-bit RSA keys with PEM encoding
- **Certificate Creation**: X.509 certificate generation with user identity binding

### Routes (routes.py)
- **Authentication**: Registration with automatic key/certificate generation, login with certificate validation
- **Document Management**: Upload, download, and listing with integrity verification
- **Digital Signatures**: Document signing and signature verification workflows
- **Dashboard**: User activity overview and system statistics

### Templates
- **Responsive Design**: Bootstrap-based UI with consistent navigation and user experience
- **Security Indicators**: Visual feedback for cryptographic operations and verification status
- **Form Validation**: Client and server-side validation for secure data input

## Data Flow

### User Registration Flow
1. User provides username, email, and password
2. System generates RSA key pair (2048-bit)
3. X.509 certificate created binding public key to user identity
4. User record created with encrypted password and PKI credentials
5. Automatic login with session establishment

### Document Upload Flow
1. File upload with size and type validation
2. SHA-256 hash calculation for integrity verification
3. Secure file storage with metadata persistence
4. Document record creation with owner association

### Digital Signature Flow
1. User selects document for signing
2. Document hash signed with user's private key
3. Signature stored with algorithm metadata and timestamp
4. Verification available through public key validation

### Document Verification Flow
1. File integrity check via SHA-256 hash comparison
2. Digital signature verification using signer's public key
3. Certificate chain validation (when CA implementation complete)
4. Comprehensive verification report generation

## External Dependencies

### Python Packages
- **Flask**: Web framework with SQLAlchemy integration
- **cryptography**: RSA operations, X.509 certificates, and digital signatures
- **Flask-Login**: Session management and user authentication
- **Werkzeug**: Password hashing and file handling utilities

### Frontend Dependencies
- **Bootstrap 5**: CSS framework with dark theme support
- **Feather Icons**: SVG icon library for UI consistency

### System Dependencies
- **File System**: Local storage for uploaded documents
- **Database**: SQLite (development) with PostgreSQL support for production

## Deployment Strategy

### Development Configuration
- **Database**: SQLite with file-based storage
- **File Storage**: Local filesystem with configurable upload directory
- **Debug Mode**: Enabled with detailed error logging
- **Session Security**: Development secret key with environment override option

### Production Considerations
- **Database**: PostgreSQL with connection pooling and health checks
- **File Storage**: Scalable storage solution for document persistence
- **SSL/TLS**: HTTPS enforcement for cryptographic material protection
- **Environment Variables**: Secure configuration management for secrets
- **Proxy Support**: Werkzeug ProxyFix for reverse proxy deployments

### Security Hardening
- **Key Storage**: Secure private key storage with potential HSM integration
- **Certificate Management**: CA certificate validation and revocation support
- **Session Security**: Strong session keys with secure cookie configuration
- **File Validation**: Enhanced file type and content validation
- **Audit Logging**: Comprehensive security event logging for compliance

### Scalability Features
- **Database Optimization**: Connection pooling and query optimization
- **File Management**: Chunked upload support for large documents
- **Caching**: Session and static content caching strategies
- **Load Balancing**: Stateless design supporting horizontal scaling

The application demonstrates practical PKI implementation suitable for academic coursework while providing a foundation for real-world secure document sharing systems.