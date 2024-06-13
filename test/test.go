package main

import (
	"log"
	"net"
)

func main() {
	var resolvedHostName string
	var resolvedIPString string
	var resolvedPort uint16
	log.Printf("开始解析Srv地址:%s", "_wg._udp.sismoe.top")
	// 指定要解析的 SRV 记录
	_, srvs, err := net.LookupSRV("wg", "udp", "sismoe.top")
	if err != nil {
		log.Printf("解析Srv地址失败,Error:%v", err)
		return
	}
	log.Printf("srvs输出=======%v\n", srvs)
	// 输出解析结果
	for _, srv := range srvs {
		log.Printf("输出=======%v:%v\n", srv.Target, srv.Port)
		resolvedHostName = srv.Target
		resolvedPort = srv.Port
	}
	iprecords, _ := net.LookupIP(resolvedHostName)
	for _, ipbyte := range iprecords {
		log.Printf("[]byte ip:%v\n", ipbyte)
		log.Printf("[]byte ip T:%T\n", ipbyte)
		resolvedIPString = ipbyte.To16().String()
		log.Printf("解析Srv地址结果:%s %d", resolvedIPString, resolvedPort)
	}
	log.Printf("解析Srv地址结果:%s %d", resolvedIPString, resolvedPort)
}
