package ip4p

import (
	"fmt"
	"strconv"
	"strings"
)

// 16进制字符串转int
func stringTohex(hexString string) int64 {
	// 将HEX字符串转换为16进制值
	hexValue, err := strconv.ParseInt(hexString, 16, 64)
	if err != nil {
		fmt.Println("转换错误:", err)
		return 0
	}
	return hexValue
}

func ResolveIp4p(ip4p string) (string, uint16) {
	//var ip4p string = "2001::4443:7416:cf3"
	arr := strings.Split(ip4p, ":")
	port := int(stringTohex(arr[2]))
	ipab := stringTohex(arr[3])
	ipcd := stringTohex(arr[4])
	ipa := ipab >> 8
	ipb := ipab & 0xff
	ipc := ipcd >> 8
	ipd := ipcd & 0xff
	ip := strconv.FormatInt(ipa, 10) + "." + strconv.FormatInt(ipb, 10) + "." + strconv.FormatInt(ipc, 10) + "." + strconv.FormatInt(ipd, 10)
	fmt.Println("端口:" + strconv.Itoa(port))
	fmt.Println("ip地址:" + ip)
	return ip, uint16(port)
}
