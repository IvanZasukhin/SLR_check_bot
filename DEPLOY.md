# Инструкция по публикации на GitHub

## 1. Создание репозитория

1. Перейдите на https://github.com/new
2. Создайте репозиторий `slr-check-bot`
3. Не ставьте галочку "Initialize with README"

## 2. Инициализация Git

```bash
cd C:\Users\i8904\Desktop\SLR_chek_bot
git init
git add .
git commit -m "Initial commit: SLR Check Bot"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/slr-check-bot.git
git push -u origin main
```

## 3. Сборка EXE

```bash
# В корневой папке проекта
build.bat
```

Результат: `dist/SLRCheckBot.exe`

## 4. Создание релиза

1. Архивируйте `dist/SLRCheckBot.exe` в `SLRCheckBot.zip`
2. Перейдите в GitHub → Releases → Draft a new release
3. Tag: `v0.1.0`
4. Приложите архив с EXE

## 5. Что добавить позже

- [ ] Иконку приложения (`icon.ico`)
- [ ] CI/CD (GitHub Actions) для авто-сборки
- [ ] Unit тесты
- [ ] Кодовую подпись EXE (чтобы не ругался антивирус)
