@echo off

setlocal

if exist GetSystemInfo.exe (
	GetSystemInfo.exe > ll_systeminfo.xml
)
if exist AntiExploitation.exe (
	AntiExploitation.exe > ll_ae.xml
)

endlocal