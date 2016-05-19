@echo off

setlocal

if exist GetSystemInfo.exe (
   GetSystemInfo.exe > ll_systeminfo.xml
)

if exist GetAVStatus.exe (
   rem ll_av.xml will be created in the same directory this batch file is run from
   GetAVStatus.exe > ll_av.xml
)


set PSPATH=%windir%\System32\WindowsPowerShell\v1.0\powershell.exe

if exist "%PSPATH%" (
   if exist Get-SystemInfo.ps1 (
      rem ps_ll_systeminfo.xml will be created by Get-SystemInfo.ps1 in the same directory this batch file is run from
      "%PSPATH%" -ExecutionPolicy Bypass -NoProfile -NonInteractive -File Get-SystemInfo.ps1
   )
)

endlocal