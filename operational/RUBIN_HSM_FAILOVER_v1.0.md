# RUBIN HSM Failover Protocol v1.0

Status: OPERATIONAL (non-consensus)
Scope: Секвенсеры и валидаторы использующие HSM для хранения приватных ключей

## Проблема

FIPS 140-3 требует чтобы приватные ключи хранились внутри HSM. При потере доступа к HSM нода не должна:
- упасть тихо (silent failure) — опасно для сети
- использовать ключ из памяти как fallback — нарушает FIPS boundary
- продолжать подписывать без HSM — нарушает key custody policy

## Три состояния ноды

```
NORMAL          — HSM доступен, подписи работают
READ_ONLY       — HSM недоступен, верификация работает, подписи отключены
FAILED          — HSM недоступен > MAX_HSM_FAILOVER_WAIT, нода останавливается
```

Переходы:

```
NORMAL → READ_ONLY   : HSM health check fails (3 consecutive)
READ_ONLY → NORMAL   : HSM health check passes (1 success)
READ_ONLY → FAILED   : timeout MAX_HSM_FAILOVER_WAIT exceeded
FAILED → NORMAL      : только ручной рестарт с `--hsm-override` флагом
```

## Конфигурация

В `rubin-node.env`:

```env
# Период health check HSM (секунды)
RUBIN_HSM_HEALTH_INTERVAL=10

# Количество consecutive failures до перехода в READ_ONLY
RUBIN_HSM_FAIL_THRESHOLD=3

# Максимальное время в READ_ONLY до FAILED (секунды). 0 = бесконечно (не рекомендуется)
RUBIN_HSM_FAILOVER_TIMEOUT=300

# Алерт webhook (опционально) — вызывается при переходе в READ_ONLY и FAILED
RUBIN_HSM_ALERT_WEBHOOK=https://ops.example.com/alerts/hsm
```

## KEK хранение и keywrap flow

Приватный ключ в памяти существует только в wrapped (зашифрованном) виде. Расшифровка происходит только внутри HSM boundary. Поток:

```
1. Нода стартует
2. Запрашивает KEK у HSM через PKCS#11: C_WrapKey / C_GetAttributeValue
3. HSM возвращает wrapped blob ключа
4. Нода хранит wrapped blob в памяти (plaintext никогда не попадает в process memory)
5. При необходимости подписать:
   a. Передаёт digest в HSM: C_SignInit + C_Sign
   b. HSM подписывает внутри, возвращает подпись
   c. Plaintext ключ никогда не покидает HSM
6. HSM health check каждые RUBIN_HSM_HEALTH_INTERVAL секунд:
   a. PKCS#11 C_GetSlotInfo или пустой C_Sign вызов
   b. Failure → счётчик++
   c. Счётчик >= FAIL_THRESHOLD → READ_ONLY
```

`rubin_wc_aes_keywrap` / `rubin_wc_aes_keyunwrap` используются для:
- **Offline backup**: экспорт зашифрованного ключа на cold storage перед заменой HSM
- **HSM-to-HSM migration**: перенос ключа между двумя HSM через encrypted blob
- **Test/dev**: замена PKCS#11 в средах без физического HSM

## Failover последовательность

### Сценарий: HSM перестал отвечать

```
T=0s   NORMAL — нормальная работа
T=10s  health check #1 — FAIL — счётчик=1
T=20s  health check #2 — FAIL — счётчик=2
T=30s  health check #3 — FAIL — счётчик=3 ≥ FAIL_THRESHOLD
       → ПЕРЕХОД В READ_ONLY
       → АЛЕРТ оператору (webhook + stderr)
       → Логировать: "HSM unreachable, entering READ_ONLY mode"
       → Все входящие Sign запросы → HTTP 503 / ошибка "HSM unavailable"
       → Верификация продолжает работать

T=30s–330s   READ_ONLY — операторы реагируют
T=330s  RUBIN_HSM_FAILOVER_TIMEOUT=300 истёк
        → ПЕРЕХОД В FAILED
        → Логировать: "HSM timeout exceeded, node shutting down"
        → АЛЕРТ (повторный)
        → Graceful shutdown (завершить текущие запросы, закрыть connections)

Оператор:
1. Проверяет физический HSM или резервный
2. Переключает на резервный HSM (меняет PKCS#11 slot в конфиге)
3. Рестартует ноду: systemctl restart rubin-node
```

### Сценарий: плановая замена HSM

```
1. Operator export (до замены):
   rubin-node keymgr export-wrapped --out /secure/backup/key_$(date +%Y%m%d).bin
   # внутри: rubin_wc_aes_keywrap(kek_from_hsm, sk_from_hsm, ...)

2. Установить новый HSM, импортировать KEK

3. Import на новый HSM:
   rubin-node keymgr import-wrapped --in /secure/backup/key_YYYYMMDD.bin
   # внутри: rubin_wc_aes_keyunwrap(new_kek, wrapped_blob, ...)

4. Verify: rubin-node keymgr verify-pubkey
   # проверяет что pubkey совпадает с ожидаемым key_id

5. Рестарт ноды
```

## Что логировать (обязательно)

Каждое событие состояния HSM MUST записываться в structured log:

```json
{
  "ts": "2026-02-18T12:00:00Z",
  "level": "WARN",
  "event": "hsm_state_change",
  "from": "NORMAL",
  "to": "READ_ONLY",
  "fail_count": 3,
  "hsm_slot": "0",
  "reason": "C_Sign timeout after 5000ms"
}
```

## Алерт формат (webhook)

POST JSON:

```json
{
  "event": "hsm_failover",
  "state": "READ_ONLY",
  "node_id": "...",
  "timestamp": "...",
  "hsm_slot": "0",
  "fail_count": 3
}
```

## Связь с keywrap PoC

`rubin_wc_aes_keywrap` / `rubin_wc_aes_keyunwrap` реализованы в shim как:
- замена PKCS#11 для dev/test окружений без HSM
- утилита для offline backup/restore ключей
- основа для интеграционного теста keymgr pipeline

В production PKCS#11 C_WrapKey/C_UnwrapKey вызывается напрямую к HSM — shim функции не используются для online операций.
