@echo off
color 0d
del /q /s %TEMP%\*
del /q /s %SystemRoot%\Temp\*
del /q /s %SystemRoot%\Prefetch\*.*
exit