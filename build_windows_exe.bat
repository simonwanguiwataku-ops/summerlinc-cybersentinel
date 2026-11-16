@echo off
setlocal
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
  echo Python 3.10+ is required. Install from https://www.python.org/downloads/windows/
  pause
  exit /b 1
)
python -m pip install --upgrade pip
python -m pip install pyinstaller
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
pyinstaller --noconfirm --clean --windowed --onedir --name CyberSentinel cybersentinel_kev.py
if errorlevel 1 (
  echo Build failed.
  pause
  exit /b 1
)
echo.
echo Build complete: dist\CyberSentinel\CyberSentinel.exe
echo Copy the entire dist\CyberSentinel folder to the target PC.
pause
