# Компиляторы и утилиты
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
GCC ?= gcc
BPFTOOL ?= bpftool

# Исходные файлы
BPF_SOURCE := better_filter.bpf.c
USER_SOURCE := better_syn_user.c
BPF_OBJECT := better_filter.bpf.o
SKEL_HEADER := better_filter.skel.h
USER_PROGRAM := better_syn_user

# Имя интерфейса по умолчанию
IFACE ?= enp0s3

# Флаги компиляции
BPF_CFLAGS := -O2 -target bpf -g -Wall
USER_CFLAGS := -Wall -O2
LDFLAGS := -lbpf -lelf

# Пути к BPF файловой системе
BPF_FS := /sys/fs/bpf
MAP_FILTER_PATH := $(BPF_FS)/filter_map
MAP_STATS_PATH := $(BPF_FS)/stats_map

.PHONY: all clean load unload debug show-maps show-stats purge

all: $(SKEL_HEADER) $(USER_PROGRAM) mount-bpf

# Генерация скелетона из объектного файла
$(SKEL_HEADER): $(BPF_OBJECT)
	$(BPFTOOL) gen skeleton $< > $@
	@echo "Generated skeleton header: $@"

# Компиляция eBPF программы
$(BPF_OBJECT): $(BPF_SOURCE)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

# Компиляция пользовательской программы (зависит от скелетона)
$(USER_PROGRAM): $(USER_SOURCE) $(SKEL_HEADER)
	$(GCC) $(USER_CFLAGS) $< -o $@ $(LDFLAGS)

# Загрузка XDP программы на интерфейс
load: $(BPF_OBJECT)
	@# Сначала выгрузите старую программу
	-sudo ip link set dev $(IFACE) xdp off
	@# Удалите старые pinned карты, если они существуют
	-sudo rm -f $(BPF_FS)/filter_map
	-sudo rm -f $(BPF_FS)/stats_map
	sudo ip link set dev $(IFACE) xdp obj $(BPF_OBJECT) sec xdp
	@echo "XDP program loaded on $(IFACE)"

# Монтирование BPF файловой системы (если не смонтирована)
mount-bpf:
	@if ! mountpoint -q $(BPF_FS); then \
		echo "Mounting BPF filesystem..."; \
		sudo mount -t bpf bpf $(BPF_FS); \
	else \
		echo "BPF filesystem already mounted"; \
	fi

# Закрепление карт в BPF FS
pin-map: mount-bpf
	@if ! sudo $(BPFTOOL) map show | grep -q "filter_map"; then \
		sudo $(BPFTOOL) map pin name filter_map $(BPF_FS)/filter_map; \
		echo "Pinned filter_map"; \
	else \
		echo "filter_map already pinned"; \
	fi
	@if ! sudo $(BPFTOOL) map show | grep -q "stats_map"; then \
		sudo $(BPFTOOL) map pin name stats_map $(BPF_FS)/stats_map; \
		echo "Pinned stats_map"; \
	else \
		echo "stats_map already pinned"; \
	fi
	@echo "Maps pinned at $(BPF_FS)/"

# Полная установка (загрузка + закрепление карт)
install: pin-map load

# Выгрузка XDP программы
unload:
	sudo ip link set dev $(IFACE) xdp off
	@echo "XDP program unloaded from $(IFACE)"

# Удаление закрепленных карт
unpin-map:
	sudo rm -f $(MAP_FILTER_PATH) $(MAP_STATS_PATH)
	@echo "Maps removed from $(BPF_FS)"

# Полная очистка (выгрузка + удаление карт + демонтирование FS)
purge: unload unpin-map
	@if mountpoint -q $(BPF_FS); then \
		echo "Unmounting BPF filesystem..."; \
		sudo umount $(BPF_FS); \
	else \
		echo "BPF filesystem not mounted"; \
	fi
	@echo "System fully purged of XDP program"

# Просмотр отладочной информации
debug:
	@echo "\n=== XDP statistics ==="
	sudo ethtool -S $(IFACE) | grep xdp || echo "No XDP stats available"
	@echo "\n=== BPF trace pipe ==="
	sudo cat /sys/kernel/debug/tracing/trace_pipe

# Просмотр карт eBPF
show-maps:
	sudo $(BPFTOOL) map show

# Просмотр статистики XDP
show-stats:
	sudo ethtool -S $(IFACE) | grep xdp || echo "No XDP stats available"

# Очистка
clean:
	rm -f $(BPF_OBJECT) $(USER_PROGRAM) $(SKEL_HEADER)
	@echo "Cleaned build files and skeleton header"
