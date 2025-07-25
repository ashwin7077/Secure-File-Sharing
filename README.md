# PKI File Sharing System

A secure Flask-based file sharing application implementing Public Key Infrastructure (PKI) for document authentication and digital signatures.

## Features

- **PKI Authentication**: User registration with automatic RSA key pair and X.509 certificate generation
- **Digital Signatures**: Sign documents with private keys for authenticity verification
- **Document Verification**: Verify signatures and file integrity using cryptographic methods
- **Secure File Storage**: SHA-256 hashing for file integrity verification
- **Web Interface**: Modern Bootstrap-based UI with dark theme support

## Security Features

- RSA 2048-bit key pairs
- X.509 digital certificates
- SHA-256 with RSA digital signatures
- File integrity verification
- Certificate validation
- Secure session management

## Quick Start

### Using Docker (Recommended)

1. Clone the repository:
```bash
git clone <repository-url>
cd pki-file-sharing
```

2. Build and run with Docker Compose:
```bash
docker-compose up --build
```

3. Access the application at `http://localhost:5000`

### Manual Installation

1. Install Python 3.11+
2. Install dependencies:
```bash
pip install -e .
```

3. Run the application:
```bash
python main.py
```

## Database

The application uses **SQLite** as the default database, stored as a file (`pki_app.db`) in the `instance/` directory. This provides:

- File-based storage (no separate database server needed)
- Cross-platform compatibility (Linux and Windows)
- Easy backup and migration
- Perfect for development and small deployments

For production with higher load, you can switch to PostgreSQL by setting the `DATABASE_URL` environment variable.

## Docker Deployment

### Basic Deployment
```bash
# Build and start the application
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the application
docker-compose down
```

### Production Deployment with Nginx
```bash
# Start with nginx reverse proxy
docker-compose --profile production up -d
```

## Environment Variables

- `SESSION_SECRET`: Secret key for session management (required for production)
- `DATABASE_URL`: Database connection string (optional, defaults to SQLite)
- `FLASK_ENV`: Environment mode (development/production)

## File Structure

```
├── app.py              # Flask application setup
├── main.py             # Application entry point
├── models.py           # Database models
├── routes.py           # Application routes
├── crypto_utils.py     # PKI cryptographic utilities
├── templates/          # HTML templates
├── static/            # CSS and static files
├── uploads/           # User-uploaded documents
├── instance/          # SQLite database location
├── Dockerfile         # Docker container configuration
└── docker-compose.yml # Docker Compose setup
```

## Usage

1. **Register**: Create an account (generates RSA keys and certificate automatically)
2. **Upload**: Upload documents to the secure repository
3. **Sign**: Digitally sign documents with your private key
4. **Verify**: Verify document authenticity and signatures
5. **Download**: Download documents with integrity verification

## Cross-Platform Support

The application runs on both Linux and Windows:

- **Docker**: Works identically on both platforms
- **SQLite**: File-based database compatible with all operating systems
- **Python**: Cross-platform Flask application
- **File Storage**: Platform-independent file handling

## Security Considerations

- Keep your private keys secure
- Use strong session secrets in production
- Enable HTTPS for production deployments
- Regularly backup the SQLite database file
- Monitor certificate expiration dates

## Development

To run in development mode:

```bash
# Set environment variables
export FLASK_ENV=development
export SESSION_SECRET=dev-secret-key

# Run the application
python main.py
```

## Production Notes

- Set a strong `SESSION_SECRET` environment variable
- Consider using PostgreSQL for higher loads
- Enable HTTPS with proper SSL certificates
- Set up regular database backups
- Monitor application logs

## License

This project is for educational purposes demonstrating PKI implementation in a web application.