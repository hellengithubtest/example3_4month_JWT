# Spring Security JWT demo

Учебный stateless-микросервис демонстрирует вход по логину и паролю, выпуск
access/refresh JWT и предметную авторизацию для управления пользователями.

## Запуск

Требуется Java 21. Gradle Wrapper включён в проект, поэтому отдельно
устанавливать Gradle не нужно.

Сгенерировать 256-битный секрет и передать его приложению в Base64-виде:

```bash
export JWT_SECRET="$(openssl rand -base64 32)"
./gradlew bootRun
```

`JWT_SECRET` не хранится в Git и не имеет значения по умолчанию. Без него
приложение не запустится. После перезапуска терминала секрет нужно задать
заново. В production его следует получать из secret storage, а не из `.env` в Git.

Сроки жизни задаются в одном месте — в `application.yml`: параметр
`jwt.access-token-expiration` равен `15m`, а `jwt.refresh-token-expiration` —
`7d`. Последний используется и для claim `exp` refresh JWT, и для поля
`expiryDate` в БД, поэтому сроки не расходятся.

Приложение: <http://localhost:8090>. Swagger UI:
<http://localhost:8090/swagger-ui/index.html>.

База H2 находится в памяти и заново заполняется из `data.sql` при каждом запуске.

## CORS и production security headers

Для локальной разработки разрешён только origin `http://localhost:3000`.
CORS использует закрытые списки:

- методы: `GET`, `POST`, `OPTIONS`;
- request headers: `Authorization`, `Content-Type`;
- credentials: отключены, потому что JWT передаётся в Bearer-заголовке;
- preflight cache: 1 час.

Wildcard `*` запрещён проверкой конфигурации. Неизвестный origin, метод или
header получает `403 Invalid CORS request` без
`Access-Control-Allow-Origin`.

Production-профиль требует явно передать список origin без fallback:

```bash
export JWT_SECRET="$(openssl rand -base64 32)"
export CORS_ALLOWED_ORIGINS="https://app.example.com,https://admin.example.com"
SPRING_PROFILES_ACTIVE=prod ./gradlew bootRun
```

В production обычно TLS завершается на доверенном reverse proxy. Профиль `prod`
включает `server.forward-headers-strategy=framework`, поэтому запрос с
доверенным `X-Forwarded-Proto: https` считается secure. Proxy должен удалять
внешние spoofed `Forwarded`/`X-Forwarded-*` и устанавливать собственные значения.

Приложение возвращает следующие заголовки:

| Заголовок | Значение |
|---|---|
| `Content-Security-Policy` | same-origin scripts/resources, запрет `object-src` и `frame-ancestors` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` только для HTTPS |

HSTS намеренно не добавляется в HTTP-ответы. `includeSubDomains` и `preload`
следует использовать только когда основной домен и все поддомены постоянно
доступны по HTTPS. Проверка после production-развёртывания:

```bash
curl -I http://api.example.com/api/users
curl -I https://api.example.com/api/users
```

В первом ответе `Strict-Transport-Security` отсутствует, во втором присутствует.

## Тестовые пользователи

Данные предназначены только для локального учебного запуска:

| Логин | Пароль | Роли | Authorities |
|---|---|---|---|
| `user1` | `password` | USER | `ROLE_USER` |
| `reader` | `password` | READ | `users:read` |
| `moderator` | `password` | READ, BLOCK | `users:read`, `users:block` |

В `data.sql` хранится BCrypt-хэш пароля. Таблицы `roles` и `user_roles`
заполняются явно. READ и BLOCK преобразуются в предметные полномочия
`users:read` и `users:block`; глобальной роли ADMIN в сервисе нет.

## Проверка login через curl

```bash
curl -i \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"password"}' \
  http://localhost:8090/api/auth/login
```

Для проверки управления пользователями заменить `user1` на `reader` или
`moderator`. Ожидается `HTTP 200` и JSON:

```json
{
  "accessToken": "eyJ...",
  "refreshToken": "eyJ...",
  "tokenType": "Bearer",
  "expiresIn": 900
}
```

Access token действует 15 минут, refresh token — 7 дней. В Swagger UI нужно
нажать **Authorize** и вставить значение `accessToken`; Swagger добавит схему
`Bearer` к HTTP-запросу.

Оба JWT содержат claim `token_type`: значение `access` используется для
доступа к API, а `refresh` — только для получения новой пары токенов. Refresh
token не принимается как Bearer-токен защищённых endpoint'ов, а access token
отклоняется endpoint'ом `/api/auth/refresh`.

Исходный refresh token возвращается только клиенту. В H2 сохраняется его
SHA-256-хэш, поэтому утечка таблицы не раскрывает готовые Bearer-токены.
SHA-256 подходит здесь потому, что JWT имеет высокую энтропию и не является
коротким пользовательским паролем.

## Refresh, logout и отзыв всех сессий

Получить новую пару токенов можно только по действующему refresh token:

```bash
curl -i \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<REFRESH_TOKEN>"}' \
  http://localhost:8090/api/auth/refresh
```

Ротация выполняется в одной транзакции с pessimistic lock: старый refresh token
помечается отозванным, а новый сохраняется атомарно. Если два запроса используют
один token одновременно, успешным будет только один.

Завершить одну сессию можно без access token, подтвердив владение её refresh
token. Повторный logout идемпотентен:

```bash
curl -i -X POST \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<REFRESH_TOKEN>"}' \
  http://localhost:8090/api/auth/logout
```

Отозвать refresh token всех сессий текущего пользователя можно только с
действующим access token:

```bash
curl -i -X POST \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  http://localhost:8090/api/auth/revoke-all
```

Оба logout-endpoint'а возвращают `204 No Content`. Уже выданные access token
остаются действительными до истечения их короткого срока; отзываются именно
refresh token, чтобы новые access token больше нельзя было получить.

## Чтение и блокировка пользователей

`GET /api/users` требует `users:read` и возвращает других пользователей без
паролей и внутренних ролей:

```bash
curl -H "Authorization: Bearer <READER_ACCESS_TOKEN>" \
  http://localhost:8090/api/users
```

`POST /api/users/{id}/block` требует `users:block`:

```bash
curl -X POST \
  -H "Authorization: Bearer <MODERATOR_ACCESS_TOKEN>" \
  http://localhost:8090/api/users/3001/block
```

READ позволяет только читать. BLOCK позволяет блокировать, а `moderator` имеет
обе роли. Пользователь не может заблокировать самого себя. После блокировки
поле `enabled` становится `false`. Новый login и запросы с ранее выданным access
token заблокированной записи отклоняются.

## Коды и JSON-ответы ошибок безопасности

Все ошибки аутентификации и авторизации возвращаются в едином JSON-формате:

```json
{
  "timestamp": "2026-11-05T09:00:00Z",
  "status": 401,
  "error": "Unauthorized",
  "message": "Authentication is required",
  "path": "/api/users"
}
```

- `400 Bad Request` — тело запроса не прошло DTO-валидацию;
- `401 Unauthorized` — неверный пароль, отсутствующий, повреждённый, просроченный
  или неподходящий JWT, отозванный refresh token либо заблокированный пользователь;
- `403 Forbidden` — access token действителен и пользователь аутентифицирован,
  но у него нет требуемой authority.

Ответы не раскрывают, существует ли указанный логин, и не включают JWT или
внутренний текст исключения.

Сервер регистрирует отклонённые JWT на уровне `WARN`, но пишет только безопасную
категорию причины, HTTP-метод и путь:

```text
JWT authentication rejected: category=EXPIRED, method=GET, path=/api/users
JWT refresh rejected: category=MALFORMED, operation=refresh
```

Используются категории `EXPIRED`, `INVALID_SIGNATURE`, `MALFORMED`,
`UNSUPPORTED`, `INVALID_FORMAT` и `INVALID`. Исходный Bearer-токен, сообщение
исключения и stack trace в лог не передаются.

## Автоматическая проверка

```bash
./gradlew test
```

`LoginFlowIntegrationTest` поднимает настоящий Spring-контекст и проверяет:

1. пользователей и связи с ролями из `data.sql`;
2. соответствие пароля `password` сохранённому BCrypt-хэшу;
3. HTTP login для USER, READ и READ+BLOCK;
4. наличие access/refresh token и время жизни access token;
5. подпись, subject, claim `token_type` и сохранение только SHA-256-хэша refresh token в H2;
6. запрет применения refresh token как access token и access token в `/refresh`;
7. успешную и конкурентную атомарную ротацию refresh token;
8. logout одной сессии и revoke-all для всех сессий пользователя;
9. единый срок refresh token для JWT и записи БД;
10. `400 Bad Request` для невалидных login и refresh DTO;
11. единый JSON и `401` для отсутствующей/невалидной аутентификации и неверного пароля;
12. категории логирования для malformed и просроченного access JWT, а также
    невалидного refresh JWT — без исходного токена и exception details.

`JwtServiceConfigurationTest` проверяет Base64-формат и минимальную длину
JWT-секрета. Интеграционные тесты генерируют свой случайный тестовый ключ и не
зависят от production-секрета.

`UserManagementIntegrationTest` проверяет прохождение JWT через фильтр и RBAC:

- USER не может читать других пользователей;
- READ читает список, но получает `403` при блокировке;
- READ+BLOCK читает и блокирует другого пользователя;
- `403` возвращается только аутентифицированному пользователю без authority;
- ответы не содержат паролей;
- самого себя заблокировать нельзя;
- заблокированная запись не может выполнить login или использовать старый access token.

`CorsAndSecurityHeadersIntegrationTest` проверяет разрешённый preflight,
отклонение неизвестных origin/method/header, CSP, `nosniff`, frame deny и
условный HSTS: заголовок отсутствует на HTTP и присутствует на HTTPS.

Собрать исполняемый Spring Boot JAR:

```bash
./gradlew bootJar
```

## Полный учебный сценарий

1. Выполнить login как `reader` и получить access token.
2. Вставить access token в Swagger и успешно вызвать `GET /api/users`.
3. Убедиться, что `POST /api/users/{id}/block` возвращает `403`.
4. Выполнить login как `moderator` и повторить оба запроса — оба должны быть успешны.
5. Проверить, что заблокированный пользователь больше не может войти.
6. После истечения access token вызвать `POST /api/auth/refresh` с refresh token.
7. Убедиться, что повторное применение старого refresh token возвращает `401`.
8. Проверить `/api/auth/logout` для одной сессии и `/api/auth/revoke-all` для всех сессий пользователя.
