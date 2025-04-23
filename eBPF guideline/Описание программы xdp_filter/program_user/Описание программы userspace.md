## Подключение библиотек

arpa/inet.h — работа с сетевыми адресами (inet_pton для преобразования IP).\
 bpf/libbpf.h, linux/bpf.h, bpf/bpf.h — заголовки для взаимодействия с eBPF-картами.\
 linux/if_ether.h, linux/if_packet.h — сетевые протоколы (Ethernet, IP).\
 unistd.h, sys/stat.h — системные вызовы (close, fstat).
## Определение пути к eBPF-карте

```

#define BPF_MAP_PATH "/sys/fs/bpf/filter_map"

```

Путь к BPF-карте, созданной XDP-программой и закрепленной (pinned) в файловой системе.

- Определение структуры для ключа карты

  Ключ (key) eBPF-карты состоит из: **be32 ip — IP-адрес (4 байта, big-endian). **be16 port — Порт (2 байта, big-endian).

- Функция добавления записи в карту

  Функция bpf_obj_get() используется для открытия eBPF-карты (или другого eBPF-объекта), который был закреплен (pinned) в файловой системе BPF.

  Прототип функции

```

int bpf_obj_get(const char *pathname);

```

Аргумент:

pathname — путь к eBPF-объекту в файловой системе BPF (/sys/fs/bpf/...).

Если успешно, возвращает файловый дескриптор (FD) eBPF-объекта (неотрицательное число).

```

void add_entry(const char *ip, const char *port) {

    int map_fd = bpf_obj_get(BPF_MAP_PATH);  // Открытие BPF-карты

    if (map_fd < 0) {

        perror("Failed to open BPF map");

        return;

    }

bpf_obj_get(BPF_MAP_PATH) — открывает карту BPF по пути.

```

- Далее идет заполнение ключа:

  inet_pton(AF_INET, ip, &key.ip) — преобразует строку IP в число (big-endian). 
  htons(atoi(port)) — преобразует порт в big-endian.

- Функция bpf_map_update_elem()

  Прототип

```

int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags);

```


Функция используется для добавления или обновления элемента в eBPF-карте.

Аргументы:

int fd -Файловый дескриптор (FD) eBPF-карты, полученный через bpf_obj_get().
const void *key -Указатель на ключ, по которому будет обновляться или добавляться элемент в карту.
const void *value -Указатель на значение, которое нужно добавить в карту.
\_\_u64 flags -Определяет поведение при обновлении элемента.

Возможные значения:

BPF_ANY (0) → Добавить или обновить существующую запись.
BPF_NOEXIST (1) → Добавить только если ключа еще нет.
BPF_EXIST (2) → Обновить только если ключ уже существует.

Возвращаемое значение:

0 → Успех (элемент добавлен или обновлен).
1 → Ошибка (например, неверный fd, размер ключа, карта заполнена).

```

    int value = 1;

    printf("Adding entry: IP=%x, Port=%x\n", ntohl(key.ip), ntohs(key.port));

    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) < 0) {

        perror("Failed to add entry");

    } else {

        printf("Added: %s:%s\n", ip, port);

    }

```

## Функция удаление записи

- Функция bpf_obj_get() для открытия eBPF-карты

```

void del_entry(const char *ip, const char *port) {

    int map_fd = bpf_obj_get(BPF_MAP_PATH);

    if (map_fd < 0) {

        perror("Failed to open BPF map");

        return;

    }

bpf_obj_get() открывает карту.

```

- Преобразование IP и порта аналогично add_entry().

```

    struct filter key = {};

    if (inet_pton(AF_INET, ip, &key.ip) != 1) {

        perror("Invalid IP address");

        close(map_fd);

        return;

    }

    key.port = htons(atoi(port));

```

- Функция bpf_map_delete_elem(map_fd, &key)

Прототип:

```

int bpf_map_delete_elem(int fd, const void *key);

```

Эта функция удаляет элемент из eBPF-карты по заданному ключу.

Аргументы:

int fd -Файловый дескриптор (FD) eBPF-карты, полученный через bpf_obj_get().
const void \*key -Указатель на ключ, по которому нужно удалить элемент из карты.

Возвращаемое значение:

0 → Успех (элемент успешно удален).
-1 → Ошибка (например, ключ не найден или неверный fd).

```

    if (bpf_map_delete_elem(map_fd, &key) < 0) {

        perror("Failed to delete entry");

    } else {

        printf("Deleted: %s:%s\n", ip, port);

    }

    close(map_fd);

```

## Вывод содержимого карты

Создается массив cmd размером 128 байт.
В этот массив будет записана строка системной команды, которую затем выполнит system().

```

snprintf(cmd, sizeof(cmd), "bpftool map dump pinned %s", BPF_MAP_PATH);

```

snprintf() записывает строку в cmd, подставляя BPF_MAP_PATH (путь к eBPF-карте).

Итоговая строка:

bpftool map dump pinned /sys/fs/bpf/filter_map

`system(cmd)` выполняет команду в терминале.
Эта команда показывает содержимое карты.

По сути, это аналог ввода команды вручную:

```

bpftool map dump pinned /sys/fs/bpf/filter_map

```

bpftool выводит список всех записей в BPF-карте.
pinned /sys/fs/bpf/filter_map → Использует прикрепленный (pinned) путь к карте filter_map.

```

void list_entries() {

    char cmd[128];

    snprintf(cmd, sizeof(cmd), "bpftool map dump pinned %s", BPF_MAP_PATH);

    system(cmd);

}

```

## Функция main()

Функция main() выполняет разбор аргументов командной строки и вызывает соответствующие функции для управления eBPF-картой. 

- Общий алгоритм работы
Проверка аргументов: если аргументов меньше 2, выводит подсказку по использованию.

- Если команда "add" и переданы IP + порт, вызывает add_entry(). Вызов add_entry(ip, port)
- Если команда "del" и переданы IP + порт, вызывает del_entry(). Вызов del_entry(ip, port)
- Если команда "list", вызывает list_entries(). Вызов list_entries()
- В противном случае сообщает об ошибке ввода.
Если всё прошло успешно, возвращает 0.

## Принцип работы программы

Она действует как обработчик команд, позволяя пользователю:

add Добавлять IP и порт в BPF-карту.
add Удалять IP и порт из BPF-карты.
list Просматривать содержимое карты.

Cинтаксис команды:
sudo ./program_user command ip port

Пример:
```

sudo ./program_user add 1.1.1.1 1

```