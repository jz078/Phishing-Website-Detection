@echo off
cd /d "%~dp0"

echo Installing required packages...
python -m pip install -r requirements.txt
if errorlevel 1 (
  echo.
  echo Failed to install dependencies.
  pause
  exit /b 1
)

echo.
echo Starting phishing detection website...
python app.py

echo.
pause
