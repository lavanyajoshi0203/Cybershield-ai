@echo off
title CyberShield AI - Java PBL Application
echo ========================================================
echo Compiling CyberShield AI (Java OOP Edition)...
echo ========================================================

if not exist "bin" mkdir bin

javac -encoding UTF-8 -d bin src\com\cybershield\model\*.java src\com\cybershield\service\*.java src\com\cybershield\repository\*.java src\com\cybershield\controller\*.java src\com\cybershield\view\*.java src\com\cybershield\Main.java

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] Compilation failed. Please make sure a Java JDK is installed on your computer.
    echo     You can install OpenJDK with: winget install EclipseAdoptium.Temurin.17.JDK
    echo.
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo ========================================================
echo Launching CyberShield AI Desktop Application...
echo ========================================================
java -cp bin com.cybershield.Main
pause
