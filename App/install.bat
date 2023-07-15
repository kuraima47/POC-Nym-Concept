@echo off
set DLL_DIR=%~dp0dll
echo DLL_DIR is %DLL_DIR%
echo Listing files in %DLL_DIR%:
for %%f in (%DLL_DIR%\*.dll) do (
    echo Copying %%f to C:\Windows\System32\
    copy /Y %%f C:\Windows\System32\
    if errorlevel 1 echo Failed to copy %%f
)