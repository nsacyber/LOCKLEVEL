@echo off

setlocal

if exist GetSystemInfo.exe (
   GetSystemInfo.exe > ll_systeminfo.xml
)

set PSPATH=%windir%\System32\WindowsPowerShell\v1.0\powershell.exe

if exist "%PSPATH%" (
   if exist Get-SystemInfo.ps1 (
      rem ps_ll_systeminfo.xml will be created by Get-SystemInfo.ps1 in the same directory this batch file is run from
      "%PSPATH%" -ExecutionPolicy Bypass -NoProfile -NonInteractive -File Get-SystemInfo.ps1
   )

   if exist LL_AW_Survey.ps1 (
      rem ll_aw.xml will be created by LL_AW_Survey.ps1 in the same directory this batch file is run from
      "%PSPATH%" -ExecutionPolicy Bypass -NoProfile -NonInteractive -File LL_AW_Survey.ps1
   )
)

endlocal