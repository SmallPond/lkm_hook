

需求：
开发一个linux lkm + app program，从内核中获取指定源IP的packet的5元组，源地址、目标地址、原端口、目标端口、协议，将相关的信息传给应用程序，应用程序将该信息保存在文件中。

目标： 稳定，高性能

app program使用Golang编写，lkm使用c编写


```bash
# make
make 

# 
```
![x](https://s3.51cto.com/wyfs02/M00/54/26/wKioL1R5veixMYuNAAHPQqUD_4A525.jpg)

# 

ioctl can not be exec

Bad file descriptor

