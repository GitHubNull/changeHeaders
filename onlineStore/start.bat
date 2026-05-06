@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo.
echo ========================================
echo   changeHeaders Plugin Test Server
echo   Modular Version
echo ========================================
echo.
python server.py
pause
