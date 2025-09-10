@echo off
REM AuthRecorder Pro Launcher for Windows
REM =====================================

echo.
echo 🚀 AuthRecorder Pro Launcher
echo =============================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python not found in PATH
    echo    Please install Python 3.8+ and add it to PATH
    echo    Download from: https://python.org
    pause
    exit /b 1
)

REM Run the launcher
python run.py

REM Keep window open if there was an error
if errorlevel 1 (
    echo.
    echo Press any key to exit...
    pause >nul
)
