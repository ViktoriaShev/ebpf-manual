### 1. [**Официальная документация ядра по BPF**](https://www.kernel.org/doc/html/latest/bpf/index.html)

Прямо из ядра Linux: описание eBPF API, helper-функций, карты (maps), ограничения и новшества в последних версиях. Всегда актуально и подробно.

---
### 2. [**Learning eBPF: Programming the Linux Kernel for Enhanced Observability, Networking, and Security** — Liz Rice](https://docs.ebpf.io/linux/)

Практичная книга, охватывающая основы eBPF: как он работает, как писать программы, применять для мониторинга и сетевой безопасности.

---
### 3. [**libbpf документация**](https://libbpf.readthedocs.io/en/)

Официальная документация к `libbpf` — низкоуровневая библиотека для загрузки eBPF-программ в ядро.

---
### 4. [**Linux Kernel Labs**](https://linux-kernel-labs.github.io/)

Учебные материалы по ядру Linux, включая разделы про eBPF. 

---
### 5. [**Elixir Bootlin** — Исходники ядра Linux 6.13.7](https://elixir.bootlin.com/linux/v6.13.7/)

Онлайн-навигация по коду ядра Linux. Очень удобно искать реализации eBPF API, структуры, макросы, особенно при работе с `libbpf`.

---
### 6. [**BCC (BPF Compiler Collection) на GitHub**](https://github.com/iovisor/bcc/tree/)

Набор высокоуровневых инструментов и библиотек для написания eBPF программ на Python и C. Полезен для быстрого создания инструментов на основе трассировки ядра.

---
### 7. [**Habr: Введение в eBPF**](https://habr.com/ru/articles/514736/)

Статья на русском языке с хорошим обзором концепции eBPF, примерами и практическим объяснением, как это всё работает. 

---
### 8. [**BPF CO-RE Reference Guide от Алексея Старовойтова (nakryiko)**](https://nakryiko.com/posts/bpf-core-reference-guide/)

Подробный гайд по BPF CO-RE (Compile Once – Run Everywhere), объясняющий, как писать переносимые eBPF-программы. 

---
### 9. [**Eunomia BPF Developer Tutorial**](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/)

Открытый репозиторий с пошаговыми eBPF-уроками, примерами и инструментами.

---

### 10. [**TCP Flags и tcpdump Cheatsheet (GitHub)**](https://gist.github.com/donovanrodriguez/c7d563873c6433af5f55e11df10128f9)

Краткий справочник по флагам TCP и их значениям в hex. Удобен при анализе сетевого трафика и работе с `tcpdump` или XDP-фильтрами на уровне пакетов.