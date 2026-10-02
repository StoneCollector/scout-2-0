@echo off
title Scout
echo ========================================================
echo   Starting Scout
echo   http://localhost:8000
echo ========================================================

cd /d "%~dp0app"
call "%~dp0.venv\Scripts\activate.bat"

python -m uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload

pause