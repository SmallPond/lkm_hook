
# 目标

开发一个linux lkm + app program，从内核中获取指定源IP的packet的5元组【源地址、目标地址、原端口、目标端口、协议】，将相关的信息传给应用程序，应用程序将该信息保存在文件中。

Golang编写 App ，C 写 LKM

# 测试环境 

- ubuntu18.04 Linux-5.4.0-70-generic
- gcc version 7.5.0
- golang 1.14
  
# How to run

1. 获取源代码

```bash
git clone https://github.com/SmallPond/lkm_hook.git
```

2. 确保 go 运行环境
```bash
$ go version
go version go1.14 linux/amd64
```

3. 编译 lkm demo
```bash
cd lkm_hook
make  
```
4. 安装内核模块
```bash
make install 
```
5. 指定动态库路径
   
非 root 情况下，使用 `export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$(pwd)/api` 添加动态库，在 `sudo` 执行时无法找到动态链接库。因此使用以下方法：

```bash
# 执行 $echo $(pwd)/api
# 将目录添加到以下文件
sudo vim /etc/ld.so.conf
# 使生效
sudo ldconfig
```
6. 运行

```bash
make run
```

另开终端 ping dingmos.com 。当然也可修改`demo/go/src/main.go` 文件中的 filters 数组，再 ping 对应地址查看程序执行结果。 


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

## 难点

- golang 不熟悉，大部分时间花在查语法上，尤其 Go 与 C 的交互部分，Go的指针用得头疼！！


