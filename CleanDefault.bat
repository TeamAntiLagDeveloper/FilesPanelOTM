@echo off
color 0d
del /q /s /f "%TEMP%\*.*"
del /q /s /f "%SystemRoot%\Temp\*.*"
del /q /s /f "%SystemRoot%\Prefetch\*.*"
del /q /s /f "%SystemRoot%\System32\winevt\Logs\*.*"
del /q /s /f "%SystemDrive%\inetpub\logs\LogFiles\*.*"
exit
