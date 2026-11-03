@echo off
REM Present WSL's Valgrind to the Windows adapter as if it were a local tool.
REM
REM The adapter invokes:  valgrind --leak-check=full --error-exitcode=1 <artifact>
REM where <artifact> is a Windows path. Everything before the last argument is a
REM flag and passes through unchanged; the last one is translated with wslpath.
REM
REM Memcheck writes to stderr and exits 1 when it finds errors, and both must
REM survive the hop, because the adapter reads the first and judges on the second.
setlocal
set "ARGS="
set "LAST="
:loop
if "%~1"=="" goto run
if not "%LAST%"=="" set "ARGS=%ARGS% %LAST%"
set "LAST=%~1"
shift
goto loop
:run
REM Only translate a genuine Windows path. The availability probe calls
REM `--version` with no artifact at all, and handing that to wslpath produced an
REM empty target and a failed probe -- the adapter would have reported Valgrind
REM as absent while it sat there working.
echo %LAST% | findstr /r /c:"^[A-Za-z]:" >nul
if errorlevel 1 (
  wsl -d Debian -- valgrind %ARGS% %LAST%
) else (
  for /f "usebackq delims=" %%p in (`wsl -d Debian -- wslpath -a "%LAST:\=/%"`) do set "TARGET=%%p"
  call :exec
)
exit /b %ERRORLEVEL%

:exec
wsl -d Debian -- valgrind %ARGS% "%TARGET%"
exit /b %ERRORLEVEL%
