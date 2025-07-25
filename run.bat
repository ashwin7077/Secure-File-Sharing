@echo off
echo Starting PKI File Sharing Application...
echo.

REM Create necessary directories if they don't exist
if not exist "instance" mkdir instance
if not exist "uploads" mkdir uploads

echo Setting environment variables...
set SESSION_SECRET=dev-secret-key-change-in-production
set DATABASE_URL=sqlite:///instance/pki_app.db

echo Starting Flask application...
echo Application will be available at: http://localhost:5000
echo Press Ctrl+C to stop the server
echo.

python main.py