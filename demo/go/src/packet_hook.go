package main
// #cgo CFLAGS: -I../../../api
// #cgo LDFLAGS: -L${SRCDIR}/../../../api -ldbhook
// #include "db_hook_api.h"
import "C"
import "fmt"
import "net"
//import "unsafe"

// 二进制 ip 转字符串
func ip_to_string(intIP uint32) string {
	var bytes [4]byte;
	bytes[3] = byte(intIP & 0xFF);
	bytes[2] = byte((intIP >> 8) & 0xFF);
	bytes[1] = byte((intIP >> 16) & 0xFF);
	bytes[0] = byte((intIP >> 24) & 0xFF);
	return net.IPv4(bytes[3], bytes[2], bytes[1], bytes[0]).String();
}

// packet 信息
type packet_info struct {
    sport    uint16 
    dport    uint16
    protocol uint8;
    saddr    uint32
    daddr    uint32;
 }

// @title    startHook
// @description   打开设备文件，开启监控
// @param     无
// @return    文件描述符 fd 
func startHook() int {
	var fd int = int(C.db_hook_open());
	// fmt.Printf("fd is %d\n", fd);
	if fd < 0 {
		fmt.Printf("startHook error\n");
	}
	return fd;
}
// @title    registerFilter
// @description   注册过滤规则（源IP）
// @param     fd 文件描述符
// @param     filter 源IP字符串，支持同时注册多个
// @return    注册 filter 的数量 
func registerFilter(fd int, filter []string) int {
	var ret,i int;
	var count int;
	count = 0;
	for i = 0; i < len(filter); i++ {
		ret = int(C.db_hook_register_filter(C.int(fd), C.CString(filter[i])));
		if ret < 0 {
			fmt.Printf("register filter stop\n");
			break;
		}
		count = count + 1;
	}
	return count;
}
// @title    getPacket
// @description  获取符合过滤规则的包（源IP相同）
// @param     fd 文件描述符
// @param     p_info 指针，返回 packet 相关数据
// @param     num 获取 num 个数据包
// @return    获取到的包数量
func getPacket(fd int, pks_info []packet_info, num int) int{
	// var pks_info [num]packet_info;
	var ret,i int;
	if num > 100 {
		num = 100;
	}
	// var db_p_info [100]C.db_packet_info;
	ret = int(C.db_get_packet(C.int(fd), C.int(num)));
	for i=0; i < ret; i++ {
		pks_info[i].saddr = uint32(C.db_p_info[i].saddr);
		pks_info[i].daddr = uint32(C.db_p_info[i].daddr);
		pks_info[i].dport = uint16(C.db_p_info[i].dport);
		pks_info[i].sport = uint16(C.db_p_info[i].sport);
		pks_info[i].protocol = uint8(C.db_p_info[i].protocol);
	}
	

	return ret;
}
// @title    stopHook
// @description  停止监控
// @param     fd 文件描述符
// @return    无
func stopHook(fd int) {
	C.db_hook_close(C.int(fd));
}