/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/services"
)

func resolveHostname(name string) (resolvedIPString string, err error) {
	maxTries := 10
	if services.StartedAtBoot() {
		maxTries *= 3
	}
	for i := 0; i < maxTries; i++ {
		if i > 0 {
			time.Sleep(time.Second * 4)
		}
		resolvedIPString, err = resolveHostnameOnce(name)
		if err == nil {
			return
		}
		if err == windows.WSATRY_AGAIN {
			log.Printf("Temporary DNS error when resolving %s, so sleeping for 4 seconds", name)
			continue
		}
		if err == windows.WSAHOST_NOT_FOUND && services.StartedAtBoot() {
			log.Printf("Host not found when resolving %s at boot time, so sleeping for 4 seconds", name)
			continue
		}
		return
	}
	return
}

func resolveHostnameOnce(name string) (resolvedIPString string, err error) {
	hints := windows.AddrinfoW{
		Family:   windows.AF_UNSPEC,
		Socktype: windows.SOCK_DGRAM,
		Protocol: windows.IPPROTO_IP,
	}
	var result *windows.AddrinfoW
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return
	}
	err = windows.GetAddrInfoW(name16, nil, &hints, &result)
	if err != nil {
		return
	}
	if result == nil {
		err = windows.WSAHOST_NOT_FOUND
		return
	}
	defer windows.FreeAddrInfoW(result)
	var v6 netip.Addr
	for ; result != nil; result = result.Next {
		if result.Family != windows.AF_INET && result.Family != windows.AF_INET6 {
			continue
		}
		addr := (*winipcfg.RawSockaddrInet)(unsafe.Pointer(result.Addr)).Addr()
		if addr.Is4() {
			return addr.String(), nil
		} else if !v6.IsValid() && addr.Is6() {
			v6 = addr
		}
	}
	if v6.IsValid() {
		return v6.String(), nil
	}
	err = windows.WSAHOST_NOT_FOUND
	return
}

func (config *Config) ResolveEndpoints() error {
	for i := range config.Peers {
		if config.Peers[i].Endpoint.IsEmpty() {
			continue
		}
		var err error
		configPort := config.Peers[i].Endpoint.Port
		//host域名
		configHostName := config.Peers[i].Endpoint.Host
		/* 解析srv */
		if configPort == 0 && (strings.Contains(configHostName, "._tcp.") || strings.Contains(configHostName, "._udp.")) {
			config.Peers[i].Endpoint.Host, config.Peers[i].Endpoint.Port = resolveSrv(configHostName)
			continue
		} else {
			config.Peers[i].Endpoint.Host, err = resolveHostname(configHostName)
			if err != nil {
				return err
			}
			//host解析ip
			configHostIp := config.Peers[i].Endpoint.Host
			/* 解析ip4p */
			if configPort == 0 && strings.Contains(configHostIp, ":") {
				config.Peers[i].Endpoint.Host, config.Peers[i].Endpoint.Port = resolveIp4p(configHostIp)
				continue
			}
		}
	}
	return nil
}

func resolveSrv(name string) (string, uint16) {
	log.Printf("开始解析Srv地址:%s", name)
	var resolvedHostName string
	var resolvedIPString string
	var resolvedPort uint16
	// 指定要解析的 SRV 记录
	hostSplit := strings.Split(name, ".")
	splitIndex := len(hostSplit)
	service := hostSplit[0][1:len(hostSplit[0])]
	proto := hostSplit[1][1:len(hostSplit[1])]
	hostArr := hostSplit[2:splitIndex]
	var hostname string
	for i := 0; i < len(hostArr); i++ {
		hostname += hostArr[i] + "."
	}
	hostname = hostname[0 : len(hostname)-1]
	log.Printf("域名分割查询参数:service:%v proto:%v hostname:%v", service, proto, hostname)
	_, srvs, err := net.LookupSRV(service, proto, hostname)
	if err != nil {
		log.Printf("解析Srv地址失败,Error:%v", err)
		return "0.0.0.0", 0
	}
	// 输出解析结果
	for _, srv := range srvs {
		resolvedHostName = srv.Target
		resolvedPort = srv.Port
	}
	iprecords, _ := net.LookupIP(resolvedHostName)
	for _, ipbyte := range iprecords {
		resolvedIPString = ipbyte.To16().String()
		continue
	}
	log.Printf("解析Srv地址结果:%s %d", resolvedIPString, resolvedPort)
	return resolvedIPString, resolvedPort
}

func resolveIp4p(name string) (resolvedIPString string, resolvedPort uint16) {
	log.Printf("开始解析ip4p地址:%s", name)
	arr := strings.Split(name, ":")
	port := stringTohex(arr[2])
	ipab := stringTohex(arr[3])
	ipcd := stringTohex(arr[4])
	ipa := ipab >> 8
	ipb := ipab & 0xff
	ipc := ipcd >> 8
	ipd := ipcd & 0xff
	ip := strconv.FormatInt(ipa, 10) + "." + strconv.FormatInt(ipb, 10) + "." + strconv.FormatInt(ipc, 10) + "." + strconv.FormatInt(ipd, 10)
	log.Printf("端口:" + strconv.FormatInt(port, 10))
	log.Printf("ip地址:" + ip)
	return ip, uint16(port)
}

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
