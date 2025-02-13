@echo off
powershell Start-Process node -ArgumentList 'index.js' -Verb RunAs -Wait
pause