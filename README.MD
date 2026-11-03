# Spring Security JWT demo

Учебное stateless-приложение демонстрирует вход по логину и паролю и выпуск
access/refresh JWT.

## Запуск

Требуется Java 21. Gradle Wrapper включён в проект, поэтому отдельно
устанавливать Gradle не нужно.

```bash
./gradlew bootRun
```

Приложение: <http://localhost:8090>. Swagger UI:
<http://localhost:8090/swagger-ui/index.html>.

База H2 находится в памяти и заново заполняется из `data.sql` при каждом запуске.

## Тестовые пользователи

Данные предназначены только для локального учебного запуска:

| Логин | Пароль | Роль |
|---|---|---|
| `user1` | `password` | USER |
| `user2` | `password` | USER |
| `admin` | `password` | ADMIN |

В `data.sql` хранится BCrypt-хэш пароля. Таблицы `roles` и `user_roles`
заполняются явно, поэтому Spring Security воспроизводимо загружает полномочия
`ROLE_USER` и `ROLE_ADMIN`.

## Проверка login через curl

```bash
curl -i \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"password"}' \
  http://localhost:8090/api/auth/login
```

Для ADMIN заменить `user1` на `admin`. Ожидается `HTTP 200` и JSON:

```json
{
  "accessToken": "eyJ...",
  "refreshToken": "eyJ...",
  "tokenType": "Bearer",
  "expiresIn": 900
}
```

Access token действует 15 минут, refresh token — 7 дней. В Swagger UI access
token вставляется через **Authorize** в формате `Bearer <token>`.

## Автоматическая проверка

```bash
./gradlew test
```

`LoginFlowIntegrationTest` поднимает настоящий Spring-контекст и проверяет:

1. пользователей и связи с ролями из `data.sql`;
2. соответствие пароля `password` сохранённому BCrypt-хэшу;
3. HTTP login для USER и ADMIN;
4. наличие access/refresh token и время жизни access token;
5. подпись, subject и сохранение refresh token в H2.

Собрать исполняемый Spring Boot JAR:

```bash
./gradlew bootJar
```

## Полный учебный сценарий

1. Выполнить `POST /api/auth/login`.
2. Скопировать `accessToken` и `refreshToken`.
3. Использовать access token в заголовке `Authorization: Bearer <token>`.
4. После истечения access token вызвать `POST /api/auth/refresh` с refresh token.
5. Использовать новую пару токенов.
