package main

import (
    "fmt"
    "os"
    "syscall"
    "unsafe"
)

const (
    // BPF 程序
    bpfProgram = `
        // 截获 TCP 报文
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, syscall.ETH_P_IP, 0, 1),
        BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 23),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, syscall.IPPROTO_TCP, 0, 1),
        // 提取 TOA 选项
        BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 54),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x14, 0, 1),
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 56),
        BPF_STMT(BPF_MISC+BPF_TAX, 0),
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 60),
        BPF_STMT(BPF_MISC+BPF_TAX, 1),
        // 传递数据到用户空间
        BPF_STMT(BPF_RET+BPF_K, (syscall.SK_WMEM << 16) | 0xFFFF),
    `
)

type bpfInstruction struct {
    Code uint16
    Jt   uint8
    Jf   uint8
    K    uint32
}

func main() {
    // 打开原始套接字
    fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
    if err != nil {
        fmt.Fprintf(os.Stderr, "failed to open socket: %v\n", err)
        os.Exit(1)
    }
    defer syscall.Close(fd)

    // 编译 BPF 程序
    program, err := compileBPFProgram(bpfProgram)
    if err != nil {
        fmt.Fprintf(os.Stderr, "failed to compile BPF program: %v\n", err)
        os.Exit(1)
    }

    // 加载 BPF 程序
    if err := syscall.SetsockoptBpf(fd, syscall.SOL_SOCKET, syscall.SO_ATTACH_BPF, program); err != nil {
        fmt.Fprintf(os.Stderr, "failed to attach BPF program: %v\n", err)
        os.Exit(1)
    }

    // 接收数据
    buf := make([]byte, 65536)
    for {
        n, _, err := syscall.Recvfrom(fd, buf, 0)
        if err != nil {
            fmt.Fprintf(os.Stderr, "failed to receive data: %v\n", err)
            continue
        }

        // 解析 TOA 选项
        if toa := parseTOA(buf[:n]); toa != nil {
            fmt.Printf("TOA: %s -> %s\n", toa.SrcIP, toa.DstIP)
        }
    }
}

// 编译 BPF 程序
func compileBPFProgram(program string) ([]syscall.RawSockFilter, error) {
    var instructions []bpfInstruction
    for _, line := range strings.Split(program, "\n") {
        line = strings.TrimSpace(line)
        if line == "" || strings.HasPrefix(line, "//") {
            continue
        }

        parts := strings.Split(line, ",")
        if len(parts) != 4 {
            return nil, fmt.Errorf("invalid BPF instruction: %s", line)
        }

        code, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 0, 16)
        if err != nil {
            return nil, fmt.Errorf("invalid BPF instruction: %s", line)
        }

        jt, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 0, 8)
        if err != nil {
            return nil, fmt.Errorf("invalid BPF instruction: %s", line)
        }

        jf, err := strconv.ParseUint(strings.TrimSpace(parts[2]), 0, 8)
        if err != nil {
            return nil, fmt.Errorf("invalid BPF instruction: %s", line)
        }

        k, err := strconv.ParseUint(strings.TrimSpace(parts[3]), 0, 32)
        if err != nil {
            return nil, fmt.Errorf("invalid BPF instruction: %s", line)
        }

        instructions = append(instructions, bpfInstruction{
            Code: uint16(code),
            Jt:   uint8(jt),
            Jf:   uint8(jf),
            K:    uint32(k),
        })
    }

    // 转换为 RawSockFilter 格式
    filters := make([]syscall.RawSockFilter, len(instructions))
    for i, inst := range instructions {
        filters[i] = syscall.RawSockFilter{
            Code: inst.Code,
            Jt:   inst.Jt,
            Jf:   inst.Jf,
            K:    inst.K,
        }
    }

    return filters, nil
}

// 解析 TOA 选项
func parseTOA(data []byte) *TOA {
    // 检查 TCP 报文长度
    if len(data) < 54 {
        return nil
    }

    // 检查 TOA 选项长度
    if data[54] != 0x14 {
        return nil
    }

    // 解析源 IP 地址和目标 IP 地址
    srcIP := net.IPv4(data[56], data[57], data[58], data[59]).String()
    dstIP := net.IPv4(data[60], data[61], data[62], data[63]).String()

    return &TOA{
        SrcIP: srcIP,
        DstIP: dstIP,
    }
}

// TOA 选项
type TOA struct {
    SrcIP string
    DstIP string
}
