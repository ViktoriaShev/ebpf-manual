eBPF программа остается прежней, так что на go была переведена программа в userspace:
## Описание функций, связанных с eBPF

### 🔧 `ebpf.LoadPinnedMap(path string, opts *ebpf.LoadPinOptions)`

Загружает уже **прикреплённую карту из BPF файловой системы** (`/sys/fs/bpf/`) по пути `path`.

```go
mapFd, err := ebpf.LoadPinnedMap("/sys/fs/bpf/filter_map", nil)
```
- Возвращает `*ebpf.Map`
- Карта должна быть предварительно создана и закреплена через `bpf_map__pin()` в C/Go
- Аналог `bpftool map pin` / `bpftool map show pinned`

---

### ✅ `mapFd.Put(key, value)`

Добавляет или обновляет элемент в eBPF-карте:

```go
mapFd.Put(key, value)
```
- Эквивалент вызова `bpf_map_update_elem()`
- Если ключ уже существует — значение перезаписывается
- Если нет — создаётся новая пара

---

### ❌ `mapFd.Delete(key)`

Удаляет элемент из eBPF-карты по ключу:
```go
mapFd.Delete(key)
```
- Аналог `bpf_map_delete_elem()`
    
- Безопасно вызывает `delete` по `key`
    
- Возвращает ошибку, если ключ не найден

---

### 📜 `bpftool map dump pinned ...`

go

```go

cmd := exec.Command("bpftool", "map", "dump", "pinned", bpfMapPath)
```
- Это уже не часть Go API, а обёртка над **внешней CLI-командой `bpftool`**
    
- Используется для отладки: вывод всех пар ключ/значение из карты

---

## 🔂 Как устроен твой код: шаги работы

1. Вручную **загружается XDP-программа**, и внутри неё карта `filter_map` создаётся и **прикрепляется** (`pin`) в `/sys/fs/bpf/filter_map`
    
2. Программа на Go:
    
    - **открывает карту**
    - **добавляет, удаляет или показывает** записи через вызовы `Put`, `Delete` и `bpftool`
        
3. Программа взаимодействует с eBPF-картой **напрямую из пространства пользователя**
    

---
