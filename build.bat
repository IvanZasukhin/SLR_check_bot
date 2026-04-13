@echo off
chcp 65001 >nul
echo ============================================
echo   SLR Check Bot - Сборка в EXE
echo ============================================
echo.

:: Проверяем Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ОШИБКА] Python не найден. Установите Python 3.10+
    pause
    exit /b 1
)

:: Устанавливаем зависимости
echo [1/3] Установка зависимостей...
pip install -r requirements.txt
if errorlevel 1 (
    echo [ОШИБКА] Не удалось установить зависимости
    pause
    exit /b 1
)

:: Собираем EXE
echo.
echo [2/3] Сборка EXE...
pyinstaller --clean SLRCheckBot.spec
if errorlevel 1 (
    echo [ОШИБКА] Ошибка сборки
    pause
    exit /b 1
)

:: Проверяем результат
echo.
echo [3/3] Проверка...
if exist "dist\SLRCheckBot.exe" (
    echo.
    echo ============================================
    echo   СБОРКА ЗАВЕРШЕНА УСПЕШНО!
    echo ============================================
    echo.
    echo Файл: dist\SLRCheckBot.exe
    echo Размер: 
    for %%A in ("dist\SLRCheckBot.exe") do echo   %%~zA байт
    echo.
    echo Для запуска требуется запуск от имени администратора!
) else (
    echo [ОШИБКА] Файл SLRCheckBot.exe не найден в dist/
)

echo.
pause
