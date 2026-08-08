@echo off
setlocal
cd /d "%~dp0.."

set CONFIG=Release
if /I "%~1"=="debug" set CONFIG=Debug
if /I "%~1"=="release" set CONFIG=Release

echo.
echo ==========================================
echo   XboxTLS13 v1.0.0 - Xbox 360 XEX Build
echo ==========================================
echo Configuration: %CONFIG%
echo.

if not defined XEDK (
    echo ERROR: XEDK is not set.
    echo Open an Xbox 360 XDK command prompt or install/configure the XDK first.
    echo.
    pause
    exit /b 1
)

set MSBUILD=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe
if not exist "%MSBUILD%" (
    echo ERROR: MSBuild.exe was not found at:
    echo %MSBUILD%
    echo.
    pause
    exit /b 1
)

"%MSBUILD%" XboxTLS13.sln /m /t:Build /p:Configuration=%CONFIG% /p:Platform="Xbox 360"
if errorlevel 1 (
    echo.
    echo BUILD FAILED.
    pause
    exit /b 1
)

echo.
echo BUILD COMPLETE.
echo Expected XEX:
echo   bin\%CONFIG%\XboxTLS13Demo.xex
echo.
pause
endlocal
