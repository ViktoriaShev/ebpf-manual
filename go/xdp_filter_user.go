package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Filter соответствует структуре filter из eBPF программы
type Filter struct {
	IP   uint32 // big-endian
	Port uint16 // big-endian
}

const bpfMapPath = "/sys/fs/bpf/filter_map"

func addEntry(ipStr, portStr string) error {
	// Открываем карту
	mapFd, err := ebpf.LoadPinnedMap(bpfMapPath, nil)
	if err != nil {
		return fmt.Errorf("open BPF map: %v", err)
	}
	defer mapFd.Close()

	// Парсим IP
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return fmt.Errorf("invalid IP address")
	}

	// Конвертируем порт
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return fmt.Errorf("invalid port: %v", err)
	}

	// Создаем ключ
	key := Filter{
		IP:   binary.BigEndian.Uint32(ip),
		Port: uint16(port),
	}

	// Значение может быть любым, важно только наличие ключа
	value := uint32(1)

	// Добавляем запись в карту
	if err := mapFd.Put(key, value); err != nil {
		return fmt.Errorf("map update failed: %v", err)
	}

	fmt.Printf("Added: %s:%s\n", ipStr, portStr)
	return nil
}

func delEntry(ipStr, portStr string) error {
	// Открываем карту
	mapFd, err := ebpf.LoadPinnedMap(bpfMapPath, nil)
	if err != nil {
		return fmt.Errorf("open BPF map: %v", err)
	}
	defer mapFd.Close()

	// Парсим IP
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return fmt.Errorf("invalid IP address")
	}

	// Конвертируем порт
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return fmt.Errorf("invalid port: %v", err)
	}

	// Создаем ключ
	key := Filter{
		IP:   binary.BigEndian.Uint32(ip),
		Port: uint16(port),
	}

	// Удаляем запись из карты
	if err := mapFd.Delete(key); err != nil {
		return fmt.Errorf("map delete failed: %v", err)
	}

	fmt.Printf("Deleted: %s:%s\n", ipStr, portStr)
	return nil
}

func listEntries() error {
	cmd := exec.Command("bpftool", "map", "dump", "pinned", bpfMapPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s add/del/list <IP> <PORT>\n", os.Args[0])
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "add":
		if len(os.Args) != 4 {
			fmt.Println("Usage: add <IP> <PORT>")
			os.Exit(1)
		}
		err = addEntry(os.Args[2], os.Args[3])
	case "del":
		if len(os.Args) != 4 {
			fmt.Println("Usage: del <IP> <PORT>")
			os.Exit(1)
		}
		err = delEntry(os.Args[2], os.Args[3])
	case "list":
		err = listEntries()
	default:
		fmt.Println("Invalid command")
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}