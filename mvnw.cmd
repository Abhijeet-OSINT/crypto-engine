@REM ----------------------------------------------------------------------------
@REM Maven Wrapper startup batch script for Windows
@REM ----------------------------------------------------------------------------
@echo off
setlocal

set DIRNAME=%~dp0
if "%DIRNAME%" == "" set DIRNAME=.
set MAVEN_PROJECTBASEDIR=%DIRNAME%

set MAVEN_JAVA_EXE="%JAVA_HOME%\bin\java.exe"
if not exist %MAVEN_JAVA_EXE% set MAVEN_JAVA_EXE=java

set WRAPPER_JAR="%MAVEN_PROJECTBASEDIR%\.mvn\wrapper\maven-wrapper.jar"
set WRAPPER_LAUNCHER=org.apache.maven.wrapper.MavenWrapperMain

if exist %WRAPPER_JAR% goto run

echo Downloading Maven Wrapper...
%MAVEN_JAVA_EXE% -Dmaven.wagon.http.ssl.insecure=true -cp %WRAPPER_JAR% %WRAPPER_LAUNCHER% %*

:run
%MAVEN_JAVA_EXE% -jar %WRAPPER_JAR% %*
if ERRORLEVEL 1 exit /b %ERRORLEVEL%
