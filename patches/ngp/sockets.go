package ngp

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	tcpTableOwnerPidAll = 5
)

var (
	iphlpapi                = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

type SocketMap = map[string]int // pid -> TCP sockets count

func MakeSocketsMap() (SocketMap, error) {
	return collectTableTCP()
}

func collectTableTCP() (SocketMap, error) {
	err := iphlpapi.Load()
	if err != nil {
		return nil, err
	}

	result := SocketMap{}
	res, err := getNetTable(procGetExtendedTcpTable.Addr(), false, windows.AF_INET, tcpTableOwnerPidAll)
	if err != nil {
		return nil, err
	}
	if len(res) < 4 {
		fmt.Printf("nil result!")
	}

	count := *(*uint32)(unsafe.Pointer(&res[0]))
	const structLen = 24
	for n, pos := uint32(0), 4; n < count && pos+structLen <= len(res); n, pos = n+1, pos+structLen {
		state := *(*uint32)(unsafe.Pointer(&res[pos]))
		if state < 1 || state > 12 {
			continue
		}
		//laddr := binary.BigEndian.Uint32(res[pos+4 : pos+8])
		//lport := binary.BigEndian.Uint16(res[pos+8 : pos+10])
		//raddr := binary.BigEndian.Uint32(res[pos+12 : pos+16])
		//rport := binary.BigEndian.Uint16(res[pos+16 : pos+18])
		pid := *(*uint32)(unsafe.Pointer(&res[pos+20]))
		str := fmt.Sprintf("%d", pid)
		result[str] = result[str] + 1
	}
	return result, nil
}

func getNetTable(fn uintptr, order bool, family int, class int) ([]byte, error) {
	var sorted uintptr
	if order {
		sorted = 1
	}
	for size, ptr, addr := uint32(8), []byte(nil), uintptr(0); ; {
		err, _, _ := syscall.Syscall6(fn, 5, addr, uintptr(unsafe.Pointer(&size)), sorted, uintptr(family), uintptr(class), 0)
		if err == 0 {
			return ptr, nil
		} else if err == uintptr(syscall.ERROR_INSUFFICIENT_BUFFER) {
			ptr = make([]byte, size)
			addr = uintptr(unsafe.Pointer(&ptr[0]))
		} else {
			return nil, fmt.Errorf("getNetTable failed: %v", err)
		}
	}
}
