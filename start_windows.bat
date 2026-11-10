@echo off
cd /d "%~dp0"
if not exist .venv (py -3 -m venv .venv)
call .venv\Scripts\activate.bat
python -m pip install -r requirements.txt
if errorlevel 1 (echo Could not install dependencies & pause & exit /b 1)
echo Open http://127.0.0.1:8000 in your browser
python -m uvicorn netsentry.main:app --host 127.0.0.1 --port 8000
pause
