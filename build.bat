@echo off

setlocal

set ARCH_FLAGS=
if "%PROCESSOR_ARCHITECTURE%"=="AMD64" set ARCH_FLAGS=/D_AMD64_
if "%PROCESSOR_ARCHITECTURE%"=="x86" set ARCH_FLAGS=/D_X86_

set CFLAGS=/nologo /std:c11 /W4 /O2 %ARCH_FLAGS% /I include /I src\core /I src\crypto /I src\sys
set OBJDIR=build\obj
set LIBDIR=build\lib

if not exist %OBJDIR% mkdir %OBJDIR%
if not exist %LIBDIR% mkdir %LIBDIR%

echo 'Compiling Sources...'
cl %CFLAGS% /c src\core\clean.c     /Fo%OBJDIR%\clean.obj || exit /b 1
cl %CFLAGS% /c src\core\context.c   /Fo%OBJDIR%\context.obj || exit /b 1
cl %CFLAGS% /c src\crypto\aead.c    /Fo%OBJDIR%\aead.obj || exit /b 1
cl %CFLAGS% /c src\crypto\aes256gcm.c /Fo%OBJDIR%\aes256gcm.obj || exit /b 1
cl %CFLAGS% /c src\crypto\argon2id.c /Fo%OBJDIR%\argon2id.obj || exit /b 1
cl %CFLAGS% /c src\crypto\blake2b.c /Fo%OBJDIR%\blake2b.obj || exit /b 1
cl %CFLAGS% /c src\crypto\chacha20.c /Fo%OBJDIR%\chacha20.obj || exit /b 1
cl %CFLAGS% /c src\sys\hwdetect.c   /Fo%OBJDIR%\hwdetect.obj || exit /b 1

echo 'Creating Static Library...'
lib /nologo /out:%LIBDIR%\butane.lib %OBJDIR%\*.obj || exit /b 1

echo 'Compiling CLI...'
cl %CFLAGS% /c src\cli\encrypt.c /Fo%OBJDIR%\encrypt.obj || exit /b 1
cl %CFLAGS% /c src\cli\decrypt.c /Fo%OBJDIR%\decrypt.obj || exit /b 1
cl %CFLAGS% /c src\cli\vault.c /Fo%OBJDIR%\vault.obj || exit /b 1
cl %CFLAGS% /c src\cli\main.c /Fo%OBJDIR%\main.obj || exit /b 1

echo 'Linking CLI...'
link /nologo /out:build\butane.exe %OBJDIR%\encrypt.obj %OBJDIR%\decrypt.obj %OBJDIR%\vault.obj %OBJDIR%\main.obj %LIBDIR%\butane.lib bcrypt.lib || exit /b 1

echo 'Compiling Tests...'
cl %CFLAGS% /c tests\test_main.c /Fo%OBJDIR%\test_main.obj || exit /b 1
cl %CFLAGS% /c tests\test_context.c /Fo%OBJDIR%\test_context.obj || exit /b 1
cl %CFLAGS% /c tests\test_blake2b.c /Fo%OBJDIR%\test_blake2b.obj || exit /b 1
cl %CFLAGS% /c tests\test_argon2id.c /Fo%OBJDIR%\test_argon2id.obj || exit /b 1
cl %CFLAGS% /c tests\test_aead.c /Fo%OBJDIR%\test_aead.obj || exit /b 1

echo 'Linking Test Runner...'
link /nologo /out:build\test_runner.exe %OBJDIR%\test_main.obj %OBJDIR%\test_context.obj %OBJDIR%\test_blake2b.obj %OBJDIR%\test_argon2id.obj %OBJDIR%\test_aead.obj %LIBDIR%\butane.lib bcrypt.lib || exit /b 1

echo 'Done: %LIBDIR%\butane.lib, build\butane.exe and build\test_runner.exe'

endlocal
