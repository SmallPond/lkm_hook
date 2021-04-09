package main

import "C"
import "fmt"


func main() {
	var ret int;
	var filters  = []string{"159.75.7.136", "192.16.1.253"};

	var fd int = startHook();
	if (fd < 0) {
		fmt.Printf("Open hook failed\n");
		return;
	}
	ret = registerFilter(fd, filters);
	if ret < 0 {
		fmt.Printf("register filter failed\n")
	}
	fmt.Printf("Registered %d filters\n", ret);
	
	var p_info packet_info ;
	for {
		ret = getPacket(fd, &p_info);
		if ret > 0 {
			fmt.Printf("SRC IP:PORT = (%s, %d) -> DST IP:PORT = (%s, %d) \n",
						ip_to_string(p_info.saddr),p_info.sport, ip_to_string(p_info.daddr),p_info.dport );
		}
	}

	stopHook(fd);
}



