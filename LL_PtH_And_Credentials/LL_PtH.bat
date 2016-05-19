@ECHO OFF

hostname > tmpfile
SET /p host= < tmpfile
del tmpfile

.\GetSystemInfo.exe > ll_%host%.systeminfo
.\GetDomainRole.exe > ll_%host%.role
.\NetworkMapperMT_Driver.exe hosts.txt > ll_%host%.w2w
.\highPrivilegeAccountAuditing.exe > ll_%host%.hpau
