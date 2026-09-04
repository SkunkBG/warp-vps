# warp-vps

**Cloudflare WARP как интерфейс хоста — для нод Xray / Remnawave.**

Поднимает ядерный WireGuard-интерфейс `warp` с `Table = off`: маршрутов не
добавляется **ни одного**, маршрутизация хоста не трогается. В туннель уходит
только то, что явно привязано к интерфейсу — для Xray это `sockopt.interface`.

```bash
curl -fsSL https://raw.githubusercontent.com/SkunkBG/warp-vps/main/warp-vps.sh -o /usr/local/bin/warp-vps && chmod +x /usr/local/bin/warp-vps
```

```bash
warp-vps install && warp-vps verify --probe ai
```

---

## Почему это работает без маршрутов

Неочевидная часть схемы. `Table = off` заставляет `wg-quick` не добавлять
маршруты вообще — `add_route()` выходит на первой же строке. Как тогда пакет
находит дорогу в туннель?

За счёт намеренного поведения ядра. `net/ipv4/route.c`, ветка, где поиск
маршрута не удался, а исходящий интерфейс задан:

> *«Apparently, routing tables are wrong. Assume, that the destination is on
> link. Because we are allowed to send to iface even if it has NO routes and NO
> assigned addresses. When oif is specified, routing tables are looked up with
> only one purpose: to catch if destination is gatewayed, rather than direct.»*

То есть сокет, привязанный через `SO_BINDTODEVICE`, уходит в этот интерфейс
независимо от таблиц маршрутизации. Отсюда все свойства схемы: нечему протечь,
нечего чинить в `ip rule`, и `rp_filter` не при делах.

---

## Команды

| Команда | Что делает |
|---|---|
| `install` | Регистрирует устройство WARP, пишет интерфейс, поднимает, ставит watchdog |
| `status` | Интерфейс, handshake, endpoint, трафик и что докладывает Cloudflare |
| `verify` | Доказывает, что выход идёт через WARP; `--probe ai` проверяет сами сервисы |
| `rotate` | Переезд на другой endpoint Cloudflare |
| `outbound` | Печатает outbound Xray (`freedom` + `sockopt.interface`) и правило |
| `merge` | Вставляет их в существующий конфиг Xray, с бэкапом |
| `license` | Применяет ключ WARP+ |
| `update` | Обновляет сам себя |
| `uninstall` | Убирает интерфейс, watchdog и состояние |

Полный список опций — `warp-vps help`.

---

## Xray

```bash
warp-vps outbound --rules ai --full
```

```json
{
  "tag": "warp",
  "protocol": "freedom",
  "settings": { "domainStrategy": "UseIP" },
  "streamSettings": { "sockopt": { "interface": "warp", "tcpFastOpen": true } }
}
```

Требования к ноде: Xray должен видеть интерфейс, то есть делить сетевое
пространство имён с хостом (`network_mode: host`), и иметь `CAP_NET_ADMIN` для
привязки сокета к устройству. У ноды Remnawave это есть по умолчанию.

Подробности вставки в панель — [docs/remnawave.md](docs/remnawave.md).

---

## Чем отличается от других установщиков WARP

Схема `Table = off` + `sockopt.interface` не наша — она хорошо известна,
например по [distillium/warp-native](https://github.com/distillium/warp-native).
Отличается реализация.

### `wgcf` не используется

Обычный установщик скачивает бинарь `wgcf` с GitHub, делает `chmod +x` и
запускает от root — без подписи и без проверки контрольной суммы.

Мы обращаемся к тому же API Cloudflare напрямую через `curl`, а пару ключей
X25519 генерируем локально. Скачивать и исполнять нечего.

### `/etc/resolv.conf` не трогается

Распространённый приём — на время установки перезаписать резолвер на 1.1.1.1 и
вернуть обратно по `trap EXIT`. Если скрипт убьют `SIGKILL` или сервер уйдёт в
перезагрузку посреди установки, нода останется с чужим DNS навсегда. И это не
нужно: API прекрасно достигается тем резолвером, который на ноде уже есть.

### Watchdog умеет отступать и менять endpoint

Проверка «интерфейс жив + пинг проходит» пропускает случай, когда туннель
работает, но выходит уже не через WARP. Мы спрашиваем сам Cloudflare через
интерфейс: `warp=on` или ничего.

При отказе — экспоненциальный backoff 3 → 30 минут и **смена endpoint**.
Фиксированный интервал перезапуска при полной блокировке Cloudflare даёт
сотни рестартов WireGuard в сутки, что само по себе заметная сигнатура, и не
помогает: если заблокирован конкретный anycast-адрес, помогает только переезд.

### Проверка отвечает на правильный вопрос

`warp-vps verify --probe ai` спрашивает эндпоинты, которые честно отвечают
`curl`, и показывает, **каким сервис видит ваше соединение**:

```
https://chatgpt.com/cdn-cgi/trace   200 ip=104.28.211.187 loc=FR warp=on
https://api.openai.com/v1/models    401 (reached; needs an API key)
```

Дёргать HTML-корень сайта бесполезно: Cloudflare отбивает `curl` по TLS-отпечатку,
и `403` там приходит и с домашнего браузерного IP.

---

## Безопасность

`/etc/warp-vps/account.json` содержит приватный ключ WireGuard и bearer-токен
устройства; создаётся под `umask 077`, остаётся `0600`. `/etc/wireguard/warp.conf`
тоже `0600`.

Отозвать устройство нельзя: в API Cloudflare нет самоудаления —
у `/{apiVersion}/reg/{sourceDeviceId}` есть только `GET` и `PATCH`. При выводе
ноды из эксплуатации удаляйте файл и регистрируйте новый аккаунт.

---

## Документация

- [docs/architecture.md](docs/architecture.md) — как устроено и почему именно так
- [docs/remnawave.md](docs/remnawave.md) — вставка в панель, порядок правил
- [docs/profiles.md](docs/profiles.md) — два профиля: весь трафик и только AI
- [docs/troubleshooting.md](docs/troubleshooting.md) — когда не работает

## Лицензия

MIT — [LICENSE](LICENSE)
