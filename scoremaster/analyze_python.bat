@echo off

setlocal

set PYTHON_DIR=%SYSTEMDRIVE%\Python27
set PYTHON_EXE=%PYTHON_DIR%\python.exe
set PYTHON_SCRIPTS_DIR=%PYTHON_DIR%\Scripts
set CODE_DIR=%cd%
set PYTHON_FILE=scoremaster.py

if not exist "%PYTHON_SCRIPTS_DIR%" (
   echo "%PYTHON_SCRIPTS_DIR%" does not exist
   goto end
)

pushd "%PYTHON_SCRIPTS_DIR%"


set TOOL=pep8.exe

if exist "%TOOL%" (
   "%TOOL%" --show-source --first "%CODE_DIR%\%PYTHON_FILE%" > "%CODE_DIR%\%TOOL%.txt"
) else (
   echo "%TOOL%" does not exist
)


set TOOL=pyflakes.exe

if exist "%TOOL%" (
   "%TOOL%" "%CODE_DIR%\%PYTHON_FILE%" > "%CODE_DIR%\%TOOL%.txt"
) else (
   echo "%TOOL%" does not exist
)


set TOOL=pylint.exe

if exist "%TOOL%" (
   "%TOOL%" -d line-too-long,too-few-public-methods "%CODE_DIR%\%PYTHON_FILE%" > "%CODE_DIR%\%TOOL%.txt"
) else (
   echo "%TOOL%" does not exist
)


set TOOL=%PYTHON_DIR%\Lib\site-packages\mccabe.py

if exist "%TOOL%" (
   "%PYTHON_EXE%" -m mccabe --min 11 "%CODE_DIR%\%PYTHON_FILE%" > "%CODE_DIR%\mccabe.txt"
) else (
   echo "%TOOL%" does not exist
)

popd

:end

endlocal