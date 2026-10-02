@echo off
title El Banco Test Target (Port 5000)
echo ========================================================
echo   Starting El Banco Target Server
echo   Target URL: http://127.0.0.1:5000
echo ========================================================

cd /d "%~dp0"
python app.py

pause
