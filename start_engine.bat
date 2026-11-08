@echo off
TITLE Audit System Pipeline Orchestrator

echo =======================================================
echo   PERFORMING SYSTEM PRE-FLIGHT CHECK...
echo =======================================================

:: 0. CHECK FOR OLLAMA & AUTO-INSTALL IF MISSING
where ollama >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [WARNING] Ollama AI Engine is missing on this machine.
    echo [INFO] Downloading official installer from Ollama.com...
    curl -L -o "%TEMP%\OllamaSetup.exe" "https://ollama.com/download/OllamaSetup.exe"
    
    echo [ACTION REQUIRED] Please click "Install" on the setup window that appears...
    start /wait "" "%TEMP%\OllamaSetup.exe"
    
    echo [INFO] Downloading Llama 3.2 AI Brain ^(This requires Wi-Fi and takes a few minutes^)...
    "%LOCALAPPDATA%\Programs\Ollama\ollama.exe" pull llama3.2
    
    echo =======================================================
    echo   INSTALLATION COMPLETE! 
    echo   Please CLOSE this black window and double-click the 
    echo   script one more time to launch the application.
    echo =======================================================
    pause
    exit
) ELSE (
    echo [SUCCESS] Ollama Engine detected.
)

:: Dynamically grab the exact folder this script is sitting inside
set "PROJECT_DIR=%~dp0"

echo =======================================================
echo   STARTING SECURITY AUDIT SYSTEM MICROSERVICES
echo =======================================================

:: 1. Launch Ollama Engine
echo Launching Stage 2 AI Engine (Ollama)...
start "1. Ollama (Llama 3.2)" cmd /k "ollama run llama3.2"

timeout /t 3 /nobreak > nul

:: 2. Launch FastAPI Backend
echo Launching Stage 1 Extractor API (FastAPI)...
:: Use the embedded Python to run FastAPI
start "2. FastAPI Backend" cmd /k "cd /d "%PROJECT_DIR%" && python -m uvicorn api_server:app --host 0.0.0.0 --port 8000"

timeout /t 6 /nobreak > nul

:: 3. Launch Streamlit Dashboard
echo Launching Presentation Layer (Streamlit)...
:: Use the embedded Python to run Streamlit
start "3. Streamlit Dashboard" cmd /k "cd /d "%PROJECT_DIR%" && python -m streamlit run dashboard.py --server.port 8501"

echo =======================================================
echo   ALL SERVICES LAUNCHED SUCCESSFULLY!
echo =======================================================
pause