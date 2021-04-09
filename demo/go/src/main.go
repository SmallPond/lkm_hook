package main

import "C"
import "fmt"
import "os"
//import "io/ioutil"

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
	file_packet_info, err3 := os.Create("packet.txt") //创建文件

    if err3 != nil{
        fmt.Println("create file fail")
    }
	defer file_packet_info.Close()
	
	var p_info [2]packet_info ;

	for {
		// 切片传递
		ret = getPacket(fd, p_info[:], 1);
		for i:=0; i < ret ; i++  {
			var content string;
			content = fmt.Sprintf("SRC IP:PORT = (%s, %d) -> DST IP:PORT = (%s, %d) Protocol = %d\n",
						ip_to_string(p_info[i].saddr),p_info[i].sport, ip_to_string(p_info[i].daddr),p_info[i].dport, p_info[i].protocol);
			
			fmt.Printf("%s\n", content);
			_, err3 := file_packet_info.WriteString(content) //写入文件(字节数组)

			if err3 != nil{
				fmt.Println("Write file fail")
			}
			// err := ioutil.WriteFile("packet.txt", []byte(content), 0644);
			// if err != nil {
			// 	panic(err);
			// }
		}
	}

	stopHook(fd);
}



