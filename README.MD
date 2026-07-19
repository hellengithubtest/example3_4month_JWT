Запуск приложения: 
http://localhost:8090/swagger-ui/index.html

Для тестирования полного цикла:
POST /api/auth/login → скопируем accessToken и refreshToken

Нажмаем 🔒 Authorize, вставляем accessToken

Проверяем защищённый маршрут

Дожидаемся истечения токена (или используем просроченный) → получим 401

Вызываем POST /api/auth/refresh с refreshToken → получаем новую пару

Обновляем токен в Authorize и продолжаем работу