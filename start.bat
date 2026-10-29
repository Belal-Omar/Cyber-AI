@echo off
title CyberAI - AI Security Platform
color 0b

echo =====================================================================
echo                Starting CyberAI Security Platform
echo =====================================================================
echo.
echo [1/2] Launching Backend API (FastAPI) on http://localhost:8000 ...
start "CyberAI - Backend API (Port 8000)" cmd /k "cd /d ""%~dp0backend"" && .\venv\Scripts\uvicorn.exe app.main:app --reload --port 8000"

echo [2/2] Launching Frontend UI (Vite) on http://localhost:5173 ...
start "CyberAI - Frontend UI (Port 5173)" cmd /k "cd /d ""%~dp0frontend"" && npm run dev"

echo [3/3] Launching Vulnerable Test Target on http://127.0.0.1:5050 ...
start "CyberAI - Test Target (Port 5050)" cmd /k "cd /d ""%~dp0"" && .\backend\venv\Scripts\python.exe vulnerable_test_target.py"

echo.
echo =====================================================================
echo  Services started successfully!
echo.
echo  * Frontend Web App:   http://localhost:5173
echo  * Backend API Docs:   http://localhost:8000/docs
echo  * Test Target (5050): http://127.0.0.1:5050
echo  * Default Login:      admin@cyberai.io / admin123
echo =====================================================================
echo.
echo You can minimize this window or press any key to close this launcher.
pause > nul
