# 451-panel-ddos-v1 - Description rapide du programme.
# Copyright (C) 2026 uhqtools-on
# This file is part of 451-panel-ddos-v1.
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program. If not, see https://www.gnu.org/licenses/.


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
