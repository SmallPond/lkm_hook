
# 目标

开发一个linux lkm + app program，从内核中获取指定源IP的packet的5元组【源地址、目标地址、原端口、目标端口、协议】，将相关的信息传给应用程序，应用程序将该信息保存在文件中。

app program使用Golang编写，lkm使用c编写

# 测试环境 

ubuntu18.04 Linux-5.4.0-70-generic


# 设计思路

## LKM
1. LKM 使用 netfilter 获取网络数据包

2. LKM 生成虚拟 device 支持与用户程序的交互

- open: 打开设备
- ioctl: 注册/删除过滤规则（指定源IP地址）
- read：获取数据包
- close: 关闭设备

3. 与规则匹配的数据包存储在环形队列 kfifo 中

## App

App 方面主要解决 golang 与设备文件的交互。

1. 使用 C 封装 open, ioctl, read, close 等系统调用，源码实现参考`api`目录下相关文件。

2. 为 golang 提供一个更优雅的 API

golang 调用 C 函数以及 C 结构体都需要进行转换，因此`demo\go\src\packet_hook.go`文件对 C api 在进行了一层封装，提供以下 API。

```go
// 开启监控，返回 fd
func startHook() int
// 注册过滤器（指定源 IP 地址）
func registerFilter(fd int, filter []string) int
// 获取符合过滤规则的包（源IP相同
func getPacket(fd int, p_info * packet_info) int
// 停止监控
func stopHook(fd int)
```

3. app 实现在`demo\go\src\main.go`源文件

```bash
# make
make 

# 
```

# GO 

ioctl can not be exec

Bad file descriptor

