@echo off
setlocal
cd /d "%~dp0"

where dotnet >nul 2>nul
if errorlevel 1 (
  echo.
  echo ERROR: .NET 10 SDK not found.
  echo Install .NET 10 SDK from https://dotnet.microsoft.com/download/dotnet/10.0
  echo Then run this file again.
  echo.
  pause
  exit /b 1
)

echo Building OpenSig for Windows x64...
dotnet publish "OpenSig.csproj" -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=none -p:DebugSymbols=false -o "%~dp0dist"
if errorlevel 1 (
  echo.
  echo Build failed. Check messages above.
  pause
  exit /b 1
)
echo.
echo SUCCESS: "%~dp0dist\OpenSig.exe"
echo You can copy OpenSig.exe to any Windows x64 PC.
echo.
pause
