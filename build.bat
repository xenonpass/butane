@echo off

setlocal

set CFLAGS=/nologo /std:c11 /W4 /O2 /I include /I src\core /I src\crypto /I src\sys
set OBJDIR=build\obj
set LIBDIR=build\lib

if not exist %OBJDIR% mkdir %OBJDIR%
if not exist %LIBDIR% mkdir %LIBDIR%

echo 'Compiling Sources...'
cl %CFLAGS% /c src\core\clean.c     /Fo%OBJDIR%\clean.obj
cl %CFLAGS% /c src\core\context.c   /Fo%OBJDIR%\context.obj
cl %CFLAGS% /c src\crypto\aead.c    /Fo%OBJDIR%\aead.obj
cl %CFLAGS% /c src\crypto\aes256gcm.c /Fo%OBJDIR%\aes256gcm.obj
cl %CFLAGS% /c src\crypto\argon2id.c /Fo%OBJDIR%\argon2id.obj
cl %CFLAGS% /c src\crypto\blake2b.c /Fo%OBJDIR%\blake2b.obj
cl %CFLAGS% /c src\crypto\chacha20.c /Fo%OBJDIR%\chacha20.obj
cl %CFLAGS% /c src\sys\hwdetect.c   /Fo%OBJDIR%\hwdetect.obj

echo 'Creating Static Library...'
lib /nologo /out:%LIBDIR%\butane.lib %OBJDIR%\*.obj

echo 'Done: %LIBDIR%\butane.lib'

endlocal
