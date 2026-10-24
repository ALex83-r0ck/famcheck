@echo off
rem Doppelklick-Start: richtet beim ersten Mal alles ein und startet dann den Plug-and-Play-Modus.
cd /d "%~dp0"
if not exist .venv (
    echo Erstinstallation ...
    python -m venv .venv || (echo Python nicht gefunden. Bitte von python.org installieren. & pause & exit /b 1)
    .venv\Scripts\python -m pip install -q -r requirements.txt
)
if not exist "%LOCALAPPDATA%\famcheck\platform-tools\adb.exe" (
    where adb >nul 2>nul || .venv\Scripts\python -m famcheck setup
)
.venv\Scripts\python -m famcheck watch
pause
