@echo off
title IP Scanner v0.1.0 - by TarikPro43391
color 0A

echo ============================================
echo   IP Scanner v0.1.0
echo   by TarikPro43391
echo ============================================
echo.

cd /d "%~dp0"

REM Python kurulu mu kontrol et
python --version >nul 2>&1
if errorlevel 1 (
    echo [HATA] Python bulunamadi. Once Python yukleyin: https://python.org
    pause
    exit /b 1
)

REM Sanal ortam yoksa olustur
if not exist "venv\" (
    echo [*] Sanal ortam olusturuluyor...
    python -m venv venv
)

echo [*] Sanal ortam aktif ediliyor...
call venv\Scripts\activate.bat

echo [*] Bagimliliklar kontrol ediliyor...
pip install -r requirements.txt --quiet --disable-pip-version-check

echo.
echo [*] Sunucu baslatiliyor...
echo [*] Tarayicida ac: http://localhost:5000
echo [*] Kapatmak icin bu pencereyi kapatabilirsin (CTRL+C)
echo.

start "" http://localhost:5000
python app.py

pause
