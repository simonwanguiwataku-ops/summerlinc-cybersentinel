@echo off
title Summerlinc CyberSentinel AI - Live KEV
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
  echo Python 3.10 or later was not found.
  echo Install Python from https://www.python.org/downloads/windows/
  echo Ensure "Add Python to PATH" is selected.
  pause
  exit /b 1
)
python cybersentinel_kev.py
if errorlevel 1 (
  echo.
  echo CyberSentinel closed with an error.
  pause
)
