from app import db
from flask_login import UserMixin
from datetime import datetime
import json

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    
    # PKI fields
    private_key_pem = db.Column(db.Text, nullable=False)
    public_key_pem = db.Column(db.Text, nullable=False)
    certificate_pem = db.Column(db.Text, nullable=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    documents = db.relationship('Document', backref='owner', lazy=True)
    signatures = db.relationship('DocumentSignature', backref='signer', lazy=True)

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)  # SHA256 hash for integrity
    content_type = db.Column(db.String(100))
    file_size = db.Column(db.Integer)
    
    # Foreign key
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    signatures = db.relationship('DocumentSignature', backref='document', lazy=True, cascade='all, delete-orphan')

class DocumentSignature(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    signature = db.Column(db.Text, nullable=False)  # Base64 encoded signature
    signature_algorithm = db.Column(db.String(50), default='SHA256withRSA')
    
    # Foreign keys
    document_id = db.Column(db.Integer, db.ForeignKey('document.id'), nullable=False)
    signer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    signed_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Verification status
    is_verified = db.Column(db.Boolean, default=False)
    verification_message = db.Column(db.Text)

class CertificateAuthority(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), default='PKI File Sharing CA')
    private_key_pem = db.Column(db.Text, nullable=False)
    public_key_pem = db.Column(db.Text, nullable=False)
    certificate_pem = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
