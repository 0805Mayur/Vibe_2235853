@echo off
REM Quick start for local dev
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
start cmd /k python backend\main.py
start cmd /k python frontend\app.py 