@echo off
setlocal enabledelayedexpansion
TITLE Security Audit Installer
echo ===================================================
echo Environment Setup
echo ===================================================

cd /d "%~dp0"

echo [1/3] Checking for Python 3.9+ installation...
where python >nul 2>nul

if %ERRORLEVEL% equ 0 (
    :: Python exists, but we need to verify it is 3.9 or higher
    python -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" 2>nul
    if !ERRORLEVEL! equ 0 (
        echo [SUCCESS] Compatible Python version detected.
        set "PYTHON_CMD=python"
        goto :install_deps
    ) else (
        echo [INFO] Existing Python is older than 3.9. A newer version is required.
    )
) else (
    echo [INFO] Global Python not found.
)

:: If the script reaches this point, a suitable Python version was not found.
echo.
echo [INFO] Initiating automated Python 3.11 installation...
echo Downloading official Python installer (this may take a moment)...
powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe' -OutFile 'python_installer.exe'"

echo Installing Python silently...
:: /quiet: Hides the UI. 
:: InstallAllUsers=0: Installs only for the current user so it doesn't trigger a UAC Admin prompt.
:: PrependPath=1: Automatically checks the "Add to PATH" box.
start /wait python_installer.exe /quiet InstallAllUsers=0 PrependPath=1 Include_test=0 Include_doc=0

echo Cleaning up installer...
del python_installer.exe

:: Note: The Windows PATH variable does not update in a command window that is already open.
:: To fix this without forcing the user to restart the script, we map the command directly to the new install path.
set "PYTHON_CMD=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"

if not exist "!PYTHON_CMD!" (
    echo [ERROR] Python installation failed or was interrupted.
    echo Please install Python manually from python.org and ensure "Add to PATH" is checked.
    pause
    exit /b
)
echo [SUCCESS] Python 3.11 installed successfully.

:install_deps
echo.
echo [2/3] Upgrading PIP to the latest version...
"!PYTHON_CMD!" -m pip install --upgrade pip

echo.
echo [3/3] Installing Required Libraries (This may take a while)...
"!PYTHON_CMD!" -m pip install -r requirements.txt

echo.
echo ===================================================
echo INSTALLATION COMPLETE!
echo You can now run start_architecture.bat
echo ===================================================
pause