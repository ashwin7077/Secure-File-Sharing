import os
import uuid
import secrets
from datetime import datetime, timedelta
from flask import render_template, request, redirect, url_for, flash, send_file, jsonify, current_app, abort
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from app import app, db
from models import User, Document, DocumentSignature, CertificateAuthority, ShareLink, Notification
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
            
            # Username validation
            if len(username.strip()) < 3:
                flash('Username must be at least 3 characters long.', 'error')
                return render_template('register.html')
            
            if not username.replace('_', '').replace('-', '').isalnum():
                flash('Username can only contain letters, numbers, hyphens, and underscores.', 'error')
                return render_template('register.html')
            
            # Email validation
            import re
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email.strip()):
                flash('Please enter a valid email address.', 'error')
                return render_template('register.html')
            
            # Password strength validation
            if len(password) < 8:
                flash('Password must be at least 8 characters long.', 'error')
                return render_template('register.html')
            
            if not any(c.isupper() for c in password):
                flash('Password must contain at least one uppercase letter.', 'error')
                return render_template('register.html')
            
            if not any(c.islower() for c in password):
                flash('Password must contain at least one lowercase letter.', 'error')
                return render_template('register.html')
            
            if not any(c.isdigit() for c in password):
                flash('Password must contain at least one number.', 'error')
                return render_template('register.html')
            
            if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
                flash('Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?).', 'error')
                return render_template('register.html')
            
            if password != confirm_password:
                flash('Passwords do not match.', 'error')
                return render_template('register.html')
            
            # Check if user already exists (case-insensitive)
            if User.query.filter(User.username.ilike(username.strip())).first():
                flash('Username already exists. Please choose a different username.', 'error')
                return render_template('register.html')
            
            if User.query.filter(User.email.ilike(email.strip())).first():
                flash('Email already registered. Please use a different email or try logging in.', 'error')
                return render_template('register.html')
            
            # Generate key pair
            private_key_pem, public_key_pem = PKIManager.generate_key_pair()
            
            # Create certificate
            certificate_pem = PKIManager.create_certificate(username, email, public_key_pem)
            
            # Create user (strip whitespace)
            user = User(
                username=username.strip(),
                email=email.strip().lower(),
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
            
            user = User.query.filter(User.username.ilike(username.strip())).first()
            
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
            
            # Get recipient email and sharing options
            recipient_email = request.form.get('recipient_email', '').strip()
            max_downloads = int(request.form.get('max_downloads', 5))
            expiry_hours = int(request.form.get('expiry_hours', 168))  # Default 7 days
            
            # Validate recipient email if provided
            if recipient_email:
                import re
                email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                if not re.match(email_pattern, recipient_email):
                    flash('Please enter a valid recipient email address.', 'error')
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
                db.session.flush()  # Get document ID
                
                # Create share link if recipient is provided
                share_url = None
                if recipient_email:
                    share_token = secrets.token_urlsafe(32)
                    expires_at = datetime.utcnow() + timedelta(hours=expiry_hours)
                    
                    share_link = ShareLink(
                        document_id=document.id,
                        shared_by_id=current_user.id,
                        shared_with_email=recipient_email.lower(),
                        share_token=share_token,
                        expires_at=expires_at,
                        max_downloads=max_downloads
                    )
                    
                    db.session.add(share_link)
                    
                    # Create notifications
                    sender_notification = Notification(
                        user_id=current_user.id,
                        title="Document Uploaded and Shared",
                        message=f"'{original_filename}' uploaded and shared with {recipient_email}",
                        notification_type="share",
                        document_id=document.id,
                        share_link_id=share_link.id
                    )
                    db.session.add(sender_notification)
                    
                    # Try to find recipient user
                    recipient_user = User.query.filter(User.email.ilike(recipient_email)).first()
                    if recipient_user:
                        recipient_notification = Notification(
                            user_id=recipient_user.id,
                            title="New Document Shared With You",
                            message=f"{current_user.username} shared '{original_filename}' with you",
                            notification_type="share",
                            document_id=document.id,
                            share_link_id=share_link.id
                        )
                        db.session.add(recipient_notification)
                    
                    share_url = url_for('shared_download', token=share_token, _external=True)
                
                db.session.commit()
                
                if share_url:
                    flash(f'File uploaded and shared successfully! Share URL: {share_url}', 'success')
                    return render_template('upload_success.html', 
                                         document=document, 
                                         share_url=share_url,
                                         recipient_email=recipient_email)
                else:
                    flash('File uploaded successfully! You can share it from the documents page.', 'success')
                    return redirect(url_for('documents'))
                
        except Exception as e:
            logger.error(f"Upload error: {str(e)}")
            flash('An error occurred during file upload.', 'error')
    
    return render_template('upload.html')

@app.route('/documents')
@login_required
def documents():
    try:
        # Get documents user has access to: owned documents + documents shared with user
        owned_documents = Document.query.filter_by(owner_id=current_user.id).order_by(Document.uploaded_at.desc()).all()
        
        # Get documents shared with current user (via active share links)
        shared_document_ids = db.session.query(ShareLink.document_id).filter(
            ShareLink.shared_with_email == current_user.email,
            ShareLink.is_active == True,
            ShareLink.expires_at > datetime.utcnow()
        ).subquery()
        
        shared_documents = Document.query.filter(
            Document.id.in_(shared_document_ids)
        ).order_by(Document.uploaded_at.desc()).all()
        
        # Combine and remove duplicates
        all_documents = owned_documents + [doc for doc in shared_documents if doc not in owned_documents]
        
        return render_template('documents.html', documents=all_documents)
    except Exception as e:
        logger.error(f"Documents listing error: {str(e)}")
        flash('An error occurred loading documents.', 'error')
        return render_template('documents.html', documents=[])

@app.route('/download/<int:doc_id>')
@login_required
def download(doc_id):
    # Block direct downloads - only allow through shared links
    flash('Direct downloads are disabled. Please use shared links to download documents.', 'warning')
    return redirect(url_for('documents'))

@app.route('/sign/<int:doc_id>', methods=['POST'])
@login_required
def sign_document(doc_id):
    try:
        document = Document.query.get_or_404(doc_id)
        
        # Check if user has access to this document
        has_access = (
            document.owner_id == current_user.id or  # User owns the document
            ShareLink.query.filter(
                ShareLink.document_id == doc_id,
                ShareLink.shared_with_email == current_user.email,
                ShareLink.is_active == True,
                ShareLink.expires_at > datetime.utcnow()
            ).first() is not None  # Document is shared with user
        )
        
        if not has_access:
            flash('You do not have access to this document.', 'error')
            return redirect(url_for('documents'))
        
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
        
        # Create notification for document owner
        if document.owner_id != current_user.id:
            sign_notification = Notification(
                user_id=document.owner_id,
                title="Document Digitally Signed",
                message=f"{current_user.username} signed your document '{document.original_filename}'",
                notification_type="sign",
                document_id=doc_id
            )
            db.session.add(sign_notification)
        
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
        
        # Check if user has access to this document
        has_access = (
            document.owner_id == current_user.id or  # User owns the document
            ShareLink.query.filter(
                ShareLink.document_id == doc_id,
                ShareLink.shared_with_email == current_user.email,
                ShareLink.is_active == True,
                ShareLink.expires_at > datetime.utcnow()
            ).first() is not None  # Document is shared with user
        )
        
        if not has_access:
            flash('You do not have access to this document.', 'error')
            return redirect(url_for('documents'))
        
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
            
            # Create notification for sender
            sender_notification = Notification(
                user_id=current_user.id,
                title="Document Shared Successfully",
                message=f"You shared '{document.original_filename}' with {email}",
                notification_type="share",
                document_id=doc_id,
                share_link_id=share_link.id
            )
            db.session.add(sender_notification)
            
            # Try to find recipient user and create notification
            recipient_user = User.query.filter_by(email=email).first()
            if recipient_user:
                recipient_notification = Notification(
                    user_id=recipient_user.id,
                    title="New Document Shared With You",
                    message=f"{current_user.username} shared '{document.original_filename}' with you",
                    notification_type="share",
                    document_id=doc_id,
                    share_link_id=share_link.id
                )
                db.session.add(recipient_notification)
            
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
        
        # Create download notification for owner
        download_notification = Notification(
            user_id=share_link.shared_by_id,
            title="Document Downloaded",
            message=f"'{share_link.document.original_filename}' was downloaded via shared link",
            notification_type="download",
            document_id=share_link.document_id,
            share_link_id=share_link.id
        )
        db.session.add(download_notification)
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

@app.route('/notifications')
@login_required
def notifications():
    try:
        # Get all notifications for current user
        notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
        
        # Mark notifications as read when viewed
        unread_notifications = [n for n in notifications if not n.is_read]
        for notification in unread_notifications:
            notification.is_read = True
        
        if unread_notifications:
            db.session.commit()
        
        return render_template('notifications.html', notifications=notifications)
    except Exception as e:
        logger.error(f"Notifications error: {str(e)}")
        flash('An error occurred loading notifications.', 'error')
        return render_template('notifications.html', notifications=[])

@app.route('/notifications/count')
@login_required
def notification_count():
    try:
        count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        return jsonify({'count': count})
    except Exception as e:
        logger.error(f"Notification count error: {str(e)}")
        return jsonify({'count': 0})

@app.route('/mark-notification-read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    try:
        notification = Notification.query.get_or_404(notification_id)
        
        # Check if user owns the notification
        if notification.user_id != current_user.id:
            abort(403)
        
        notification.is_read = True
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Mark notification read error: {str(e)}")
        return jsonify({'success': False})

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
