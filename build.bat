@echo off
setlocal
for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do set VSPATH=%%i
if not defined VSPATH (
    echo ERROR: Visual Studio not found
    exit /b 1
)
call "%VSPATH%\Common7\Tools\VsDevCmd.bat" -arch=x64
cd /d "%~dp0"
msbuild SSLClaw.sln /p:Configuration=Release /p:Platform=x64 /v:minimal
