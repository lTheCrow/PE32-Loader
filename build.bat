@echo off

:: set output directory and executable name variables
set build_dir=bin
set exe_name=loaderc
set compiler=mingw32-gcc
set header_dir=includes

:: check the output directory
if not exist "%build_Dir%" ( 
        echo build bin output directory doesn't exist. Creating...
        mkdir "%build_dir%"
)


:: the output directory is a relative directory

:: compile with cl (MSVC C and C++ Compilers and Linker)
::"%compiler%" main.c loader.c /I "%header_dir%" -o "%build_dir%\%exe_name%".exe

:: compile with mingw32-gcc
"%compiler%" main.c loader.c -I "%header_dir%" -lkernel32 -o "%build_dir%\%exe_name%".exe

echo build success