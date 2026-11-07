@echo off
powershell.exe -NoProfile -File "%~dp0Run-BTrust-Owner-Present-QA.ps1" -App WordCraft
echo.
echo Owner-present B-Trust test exited. Review the result above.
pause
