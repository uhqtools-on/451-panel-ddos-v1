@echo off
title Python Launcher
cd /d "%~dp0"

echo [INFO] Verification des dependances...

if exist "requirements.txt" (
    echo [INFO] Installation des modules...
    py -m pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERREUR] Installation des modules echouee.
        pause
        exit /b 1
    )
) else (
    echo [INFO] Aucun requirements.txt trouve, installation ignoree.
)

echo.
echo [INFO] Lancement de main.py...
py main.py

echo.
echo [INFO] Programme termine.
pause