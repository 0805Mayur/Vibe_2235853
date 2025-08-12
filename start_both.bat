@echo off
echo ========================================
echo   AI Code Review Dashboard - Complete
echo ========================================
echo.
echo This will start both Backend and Frontend servers
echo.
echo Backend: http://localhost:8000
echo Frontend: http://localhost:5000
echo API Docs: http://localhost:8000/docs
echo.
echo Press any key to start both servers...
pause >nul 
echo.
echo Starting servers...
echo.

start "Backend Server" cmd /k "start_backend.bat"
timeout /t 3 >nul
start "Frontend Server" cmd /k "start_frontend.bat"

echo.
echo ========================================
echo Both servers are starting...
echo Check the opened windows for logs
echo ========================================
echo.
echo Frontend: http://localhost:5000
echo Backend API: http://localhost:8000
echo API Documentation: http://localhost:8000/docs
echo.
pause 