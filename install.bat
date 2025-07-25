@echo off
echo Installing PKI File Sharing Application...
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.11+ from https://python.org
    pause
    exit /b 1
)

echo Python found, checking version...
python -c "import sys; exit(0 if sys.version_info >= (3, 11) else 1)"
if errorlevel 1 (
    echo ERROR: Python 3.11+ required
    echo Current version:
    python --version
    pause
    exit /b 1
)

echo Installing dependencies...
pip install --user cryptography>=45.0.5
pip install --user email-validator>=2.2.0
pip install --user flask-login>=0.6.3
pip install --user flask>=3.1.1
pip install --user flask-sqlalchemy>=3.1.1
pip install --user gunicorn>=23.0.0
pip install --user psycopg2-binary>=2.9.10
pip install --user sqlalchemy>=2.0.41
pip install --user werkzeug>=3.1.3

if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo Installation completed successfully!
echo.
echo To run the application:
echo   python main.py
echo.
echo The application will be available at: http://localhost:5000
echo.
pause