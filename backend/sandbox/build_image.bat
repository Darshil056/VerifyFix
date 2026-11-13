@echo off
echo =======================================================
echo Building VerifyFix Multi-Runtime Sandbox Docker Image
echo (Python 3.11 + Node.js 20 LTS + Bash)
echo =======================================================

cd /d "%~dp0"
docker build -t verifyfix-sandbox:latest .

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [SUCCESS] verifyfix-sandbox:latest successfully built!
    echo Docker Desktop will now show this image in the Images tab.
) else (
    echo.
    echo [ERROR] Docker build failed. Please ensure Docker Desktop is running.
)
pause

