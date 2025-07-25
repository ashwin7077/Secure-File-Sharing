import os
import uuid
import secrets
from datetime import datetime, timedelta
from flask import render_template, request, redirect, url_for, flash, send_file, jsonify, current_app, abort
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from app import app, db
from models import User, Document, DocumentSignature, CertificateAuthority, ShareLink
from crypto_utils import PKIManager
import logging

logger = logging.getLogger(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            
            # Validation
            if not all([username, email, password, confirm_password]):
                flash('All fields are required.', 'error')
                return render_template('register.html')
            
            if password != confirm_password:
                flash('Passwords do not match.', 'error')
                return render_template('register.html')
            
            if User.query.filter_by(username=username).first():
                flash('Username already exists.', 'error')
                return render_template('register.html')
            
            if User.query.filter_by(email=email).first():
                flash('Email already registered.', 'error')
                return render_template('register.html')
            
            # Generate key pair
            private_key_pem, public_key_pem = PKIManager.generate_key_pair()
            
            # Create certificate
            certificate_pem = PKIManager.create_certificate(username, email, public_key_pem)
            
            # Create user
            user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                private_key_pem=private_key_pem,
                public_key_pem=public_key_pem,
                certificate_pem=certificate_pem
            )
            
            db.session.add(user)
            db.session.commit()
            
            flash('Registration successful! Your digital certificate has been generated.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            flash('An error occurred during registration. Please try again.', 'error')
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            
            if not username or not password:
                flash('Username and password are required.', 'error')
                return render_template('login.html')
            
            user = User.query.filter_by(username=username).first()
            
            if user and check_password_hash(user.password_hash, password):
                # Verify certificate is still valid
                is_valid, message = PKIManager.verify_certificate(user.certificate_pem)
                if not is_valid:
                    flash(f'Your certificate is invalid: {message}', 'error')
                    return render_template('login.html')
                
                login_user(user)
                flash('Login successful!', 'success')
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password.', 'error')
                
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            flash('An error occurred during login. Please try again.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        # Get user's documents
        documents = Document.query.filter_by(owner_id=current_user.id).order_by(Document.uploaded_at.desc()).all()
        
        # Get documents signed by user
        signed_docs = db.session.query(Document).join(DocumentSignature).filter(
            DocumentSignature.signer_id == current_user.id
        ).distinct().all()
        
        return render_template('dashboard.html', documents=documents, signed_docs=signed_docs)
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        flash('An error occurred loading the dashboard.', 'error')
        return render_template('dashboard.html', documents=[], signed_docs=[])

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        try:
            if 'file' not in request.files:
                flash('No file selected.', 'error')
                return render_template('upload.html')
            
            file = request.files['file']
            if file.filename == '':
                flash('No file selected.', 'error')
                return render_template('upload.html')
            
            if file:
                # Secure filename
                original_filename = file.filename
                filename = str(uuid.uuid4()) + '_' + secure_filename(original_filename)
                file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
                
                # Save file
                file.save(file_path)
                
                # Calculate file hash for integrity
                file_hash = PKIManager.calculate_file_hash(file_path)
                
                # Create document record
                document = Document(
                    filename=filename,
                    original_filename=original_filename,
                    file_path=file_path,
                    file_hash=file_hash,
                    content_type=file.content_type,
                    file_size=os.path.getsize(file_path),
                    owner_id=current_user.id
                )
                
                db.session.add(document)
                db.session.commit()
                
                flash('File uploaded successfully!', 'success')
                return redirect(url_for('dashboard'))
                
        except Exception as e:
            logger.error(f"Upload error: {str(e)}")
            flash('An error occurred during file upload.', 'error')
    
    return render_template('upload.html')

@app.route('/documents')
@login_required
def documents():
    try:
        # Get all documents (for demonstration - in production, implement proper access control)
        documents = Document.query.order_by(Document.uploaded_at.desc()).all()
        return render_template('documents.html', documents=documents)
    except Exception as e:
        logger.error(f"Documents listing error: {str(e)}")
        flash('An error occurred loading documents.', 'error')
        return render_template('documents.html', documents=[])

@app.route('/download/<int:doc_id>')
@login_required
def download(doc_id):
    try:
        document = Document.query.get_or_404(doc_id)
        
        # Verify file integrity
        current_hash = PKIManager.calculate_file_hash(document.file_path)
        if current_hash != document.file_hash:
            flash('File integrity check failed. File may have been tampered with.', 'error')
            return redirect(url_for('documents'))
        
        return send_file(
            document.file_path,
            as_attachment=True,
            download_name=document.original_filename,
            mimetype=document.content_type
        )
    except Exception as e:
        logger.error(f"Download error: {str(e)}")
        flash('An error occurred during file download.', 'error')
        return redirect(url_for('documents'))

@app.route('/sign/<int:doc_id>', methods=['POST'])
@login_required
def sign_document(doc_id):
    try:
        document = Document.query.get_or_404(doc_id)
        
        # Check if user already signed this document
        existing_signature = DocumentSignature.query.filter_by(
            document_id=doc_id,
            signer_id=current_user.id
        ).first()
        
        if existing_signature:
            flash('You have already signed this document.', 'warning')
            return redirect(url_for('documents'))
        
        # Read file content for signing
        with open(document.file_path, 'rb') as f:
            file_content = f.read()
        
        # Create signature
        signature = PKIManager.sign_data(file_content, current_user.private_key_pem)
        
        # Save signature
        doc_signature = DocumentSignature(
            signature=signature,
            document_id=doc_id,
            signer_id=current_user.id,
            is_verified=True,  # Set to True since we just created it
            verification_message="Signature created successfully"
        )
        
        db.session.add(doc_signature)
        db.session.commit()
        
        flash('Document signed successfully!', 'success')
        
    except Exception as e:
        logger.error(f"Document signing error: {str(e)}")
        flash('An error occurred while signing the document.', 'error')
    
    return redirect(url_for('documents'))

@app.route('/verify/<int:doc_id>')
@login_required
def verify_document(doc_id):
    try:
        document = Document.query.get_or_404(doc_id)
        signatures = DocumentSignature.query.filter_by(document_id=doc_id).all()
        
        verification_results = []
        
        # Verify file integrity first
        current_hash = PKIManager.calculate_file_hash(document.file_path)
        file_integrity = current_hash == document.file_hash
        
        # Read file content for signature verification
        with open(document.file_path, 'rb') as f:
            file_content = f.read()
        
        for sig in signatures:
            signer = User.query.get(sig.signer_id)
            
            # Verify signature
            is_valid_signature = PKIManager.verify_signature(
                file_content,
                sig.signature,
                signer.public_key_pem
            )
            
            # Verify signer's certificate
            is_valid_cert, cert_message = PKIManager.verify_certificate(signer.certificate_pem)
            
            verification_results.append({
                'signature': sig,
                'signer': signer,
                'is_valid_signature': is_valid_signature,
                'is_valid_cert': is_valid_cert,
                'cert_message': cert_message,
                'overall_valid': is_valid_signature and is_valid_cert and file_integrity
            })
            
            # Update signature verification status
            sig.is_verified = is_valid_signature and is_valid_cert
            sig.verification_message = f"Signature: {'Valid' if is_valid_signature else 'Invalid'}, Certificate: {cert_message}"
        
        db.session.commit()
        
        return render_template('verify.html', 
                             document=document, 
                             verification_results=verification_results,
                             file_integrity=file_integrity)
        
    except Exception as e:
        logger.error(f"Document verification error: {str(e)}")
        flash('An error occurred while verifying the document.', 'error')
        return redirect(url_for('documents'))

@app.route('/share/<int:doc_id>', methods=['GET', 'POST'])
@login_required
def share_document(doc_id):
    try:
        document = Document.query.get_or_404(doc_id)
        
        # Check if user owns the document
        if document.owner_id != current_user.id:
            flash('You can only share your own documents.', 'error')
            return redirect(url_for('documents'))
        
        if request.method == 'POST':
            email = request.form.get('email')
            expires_in_hours = int(request.form.get('expires_in_hours', 24))
            max_downloads = int(request.form.get('max_downloads', 10))
            
            if not email:
                flash('Email address is required.', 'error')
                return render_template('share.html', document=document)
            
            # Generate secure token
            share_token = secrets.token_urlsafe(32)
            expires_at = datetime.utcnow() + timedelta(hours=expires_in_hours)
            
            # Create share link
            share_link = ShareLink(
                document_id=doc_id,
                shared_by_id=current_user.id,
                shared_with_email=email,
                share_token=share_token,
                expires_at=expires_at,
                max_downloads=max_downloads
            )
            
            db.session.add(share_link)
            db.session.commit()
            
            # Generate share URL
            share_url = url_for('shared_download', token=share_token, _external=True)
            
            flash(f'Document shared successfully! Share URL: {share_url}', 'success')
            return render_template('share_success.html', 
                                 document=document, 
                                 share_link=share_link,
                                 share_url=share_url)
        
        return render_template('share.html', document=document)
        
    except Exception as e:
        logger.error(f"Document sharing error: {str(e)}")
        flash('An error occurred while sharing the document.', 'error')
        return redirect(url_for('documents'))

@app.route('/shared/<token>')
def shared_download(token):
    try:
        share_link = ShareLink.query.filter_by(share_token=token).first()
        
        if not share_link:
            flash('Invalid or expired share link.', 'error')
            return render_template('shared_error.html', 
                                 error="Share link not found.")
        
        if not share_link.can_download:
            reason = "expired" if share_link.is_expired else "download limit reached"
            if not share_link.is_active:
                reason = "deactivated"
            
            flash(f'Share link is {reason}.', 'error')
            return render_template('shared_error.html', 
                                 error=f"Share link is {reason}.")
        
        # Verify file integrity before sharing
        document = share_link.document
        current_hash = PKIManager.calculate_file_hash(document.file_path)
        if current_hash != document.file_hash:
            flash('File integrity check failed. Document may have been tampered with.', 'error')
            return render_template('shared_error.html', 
                                 error="File integrity verification failed.")
        
        # Show download page first
        return render_template('shared_download.html', 
                             share_link=share_link,
                             document=document)
        
    except Exception as e:
        logger.error(f"Shared download error: {str(e)}")
        return render_template('shared_error.html', 
                             error="An error occurred while accessing the shared document.")

@app.route('/shared/<token>/download')
def process_shared_download(token):
    try:
        share_link = ShareLink.query.filter_by(share_token=token).first()
        
        if not share_link or not share_link.can_download:
            abort(404)
        
        # Increment download count
        share_link.download_count += 1
        db.session.commit()
        
        document = share_link.document
        
        return send_file(
            document.file_path,
            as_attachment=True,
            download_name=document.original_filename,
            mimetype=document.content_type
        )
        
    except Exception as e:
        logger.error(f"Shared download processing error: {str(e)}")
        abort(404)

@app.route('/my-shares')
@login_required
def my_shares():
    try:
        # Get all share links created by current user
        share_links = ShareLink.query.filter_by(shared_by_id=current_user.id).order_by(ShareLink.created_at.desc()).all()
        return render_template('my_shares.html', share_links=share_links)
    except Exception as e:
        logger.error(f"My shares error: {str(e)}")
        flash('An error occurred loading your shares.', 'error')
        return render_template('my_shares.html', share_links=[])

@app.route('/revoke-share/<int:share_id>', methods=['POST'])
@login_required
def revoke_share(share_id):
    try:
        share_link = ShareLink.query.get_or_404(share_id)
        
        # Check if user owns the share link
        if share_link.shared_by_id != current_user.id:
            flash('You can only revoke your own share links.', 'error')
            return redirect(url_for('my_shares'))
        
        share_link.is_active = False
        db.session.commit()
        
        flash('Share link revoked successfully.', 'success')
        
    except Exception as e:
        logger.error(f"Share revocation error: {str(e)}")
        flash('An error occurred while revoking the share link.', 'error')
    
    return redirect(url_for('my_shares'))

@app.route('/certificate/<int:user_id>')
@login_required
def view_certificate(user_id):
    try:
        user = User.query.get_or_404(user_id)
        
        # Parse certificate for display
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        cert = x509.load_pem_x509_certificate(
            user.certificate_pem.encode('utf-8'),
            backend=default_backend()
        )
        
        cert_info = {
            'subject': dict(cert.subject),
            'issuer': dict(cert.issuer),
            'serial_number': str(cert.serial_number),
            'not_valid_before': cert.not_valid_before,
            'not_valid_after': cert.not_valid_after,
            'version': cert.version.name
        }
        
        return render_template('certificate.html', user=user, cert_info=cert_info)
        
    except Exception as e:
        logger.error(f"Certificate viewing error: {str(e)}")
        flash('An error occurred while viewing the certificate.', 'error')
        return redirect(url_for('dashboard'))

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500
