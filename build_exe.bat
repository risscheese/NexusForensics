@echo off
echo ============================================
echo   Nexus Forensics - Build Script
echo ============================================

echo.
echo [1/3] Checking/Installing Build Dependencies...
py -m pip install --upgrade pip
py -m pip install pyinstaller pywebview flask psutil requests

echo.
echo [2/3] Cleaning previous builds...
rmdir /s /q build dist
del /q *.spec

echo.
echo [3/3] Running PyInstaller...
REM --onefile: Bundle everything into a single .exe
REM --icon: Set the application icon
REM --add-data: Include flask templates and static files (Windows syntax uses ;)
REM --add-binary: Include the winpmem driver for memory capture
REM --hidden-import: Ensure dynamic imports are found
REM --name: The output filename

py -m PyInstaller --noconfirm --onefile --windowed --clean ^
    --icon "icon.ico" ^
    --name "NexusForensics" ^
    --add-data "templates;templates" ^
    --add-data "static;static" ^
    --add-binary "winpmem_mini_x64_rc2.exe;." ^
    --hidden-import "capture_engine" ^
    --hidden-import "routes" ^
    --hidden-import "webview" ^
    --hidden-import="engineio.async_drivers.threading" ^
    app.py

echo.
if exist "dist\NexusForensics.exe" (
    echo [SUCCESS] Build successful!
    echo Location: dist\NexusForensics.exe
) else (
    echo [ERROR] Build failed. Check the error messages above.
)
pause
