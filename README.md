# tcp_toa
a sample ebpf TCP Options Address (TOA)


TOA (TCP Option Address) 是一种 TCP 选项，用于在 TCP 报文中传输源 IP 地址和目标 IP 地址。下面是使用 eBPF 和 Golang 实现一个 TOA 的基本步骤：

1. 了解 eBPF：eBPF（Extended Berkeley Packet Filter）是一种内核扩展机制，可以在内核空间中运行自定义的程序，用于实现网络过滤、性能分析等功能。

2. 编写 eBPF 程序：使用 eBPF 工具链编写一个 eBPF 程序，用于截获 TCP 报文并提取 TOA 选项中的源 IP 地址和目标 IP 地址。

3. 加载 eBPF 程序：使用 Golang 编写一个程序，用于加载 eBPF 程序到内核中，并将截获的 TCP 报文传递给 eBPF 程序进行处理。

4. 解析 TOA 选项：在 eBPF 程序中解析 TOA 选项，并将源 IP 地址和目标 IP 地址传递给 Golang 程序进行处理。
