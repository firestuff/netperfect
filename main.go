package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mdlayher/ethernet"
	"github.com/mdlayher/lldp"
	"github.com/mdlayher/raw"
	"github.com/vishvananda/netlink"
)

func main() {
	link, err := getLink()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Network interface: %s", link.Attrs().Name)

	api, err := findApi(link)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("UniFi API URL: %s", api)

	/*
	upstream, err := getUpstream(link.Attrs().Name)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Connected to %s [%s] on %s", upstream.device, upstream.addr, upstream.port)
	*/

	unifi, err := NewClient(api)
	if err != nil {
		log.Fatal(err)
	}

	err = unifi.Login()
	if err != nil {
		log.Fatal(err)
	}
}

type upstream struct {
	device string
	port string
	addr net.Addr
}

func getUpstream(intName string) (*upstream, error) {
	intr, err := net.InterfaceByName(intName)
	if err != nil {
		return nil, err
	}

	sock, err := raw.ListenPacket(intr, 0x88cc /* LLDP ethertype */, nil)
	if err != nil {
		return nil, err
	}
	defer sock.Close()

	buf := make([]byte, intr.MTU)
	bufLen, addr, err := sock.ReadFrom(buf)
	if err != nil {
		return nil, err
	}

	ethFrame := &ethernet.Frame{}
	err = ethFrame.UnmarshalBinary(buf[:bufLen])
	if err != nil {
		return nil, err
	}

	lldpFrame := &lldp.Frame{}
	err = lldpFrame.UnmarshalBinary(ethFrame.Payload)
	if err != nil {
		return nil, err
	}

	ret := &upstream {
		addr: addr,
	}

	for _, tlv := range lldpFrame.Optional {
		switch tlv.Type {
		case lldp.TLVTypePortDescription:
			ret.port = strings.ToLower(string(tlv.Value))
		case lldp.TLVTypeSystemName:
			ret.device = string(tlv.Value)
		}
	}

	return ret, nil
}

func findApi(link netlink.Link) (string, error) {
	addrs, err := netlink.AddrList(link, 2 /* AF_INET */)
	if err != nil {
		return "", err
	}

	apis := []string{}

	for _, addr := range addrs {
		ip := binary.BigEndian.Uint32(addr.IPNet.IP.To4())
		mask := binary.BigEndian.Uint32(addr.IPNet.Mask)
		start := ip & mask
		end := ip | (^mask & 0xffffffff)

		addr_apis, err := findApis(start, end)
		if err != nil {
			return "", err
		}

		apis = append(apis, addr_apis...)
	}

	if len(apis) == 0 {
		return "", fmt.Errorf("no UniFi APIs found")
	}

	if len(apis) > 1 {
		return "", fmt.Errorf("multiple APIs found TODO")
	}

	return apis[0], nil
}

func findApis(start_ip, end_ip uint32) ([]string, error) {
	wg := sync.WaitGroup{}
	wg.Add(int(end_ip - start_ip + 1))

	ret := []string{}

	for iter := start_ip; iter <= end_ip; iter++ {
		go func(ip uint32) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), 500 * time.Millisecond)
			defer cancel()

			url := fmt.Sprintf(
				"https://%d.%d.%d.%d",
				ip >> 24 & 0xff,
				ip >> 16 & 0xff,
				ip >> 8 & 0xff,
				ip >> 0 & 0xff,
			)
			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				// TODO: should return an outer error
				return
			}

			tr := &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			}
			client := http.Client{
				Transport: tr,
			}
			resp, err := client.Do(req)
			if err != nil {
				// Probably not https
				return
			}

			set_cookie := resp.Header["Set-Cookie"]
			if len(set_cookie) != 1 || !strings.HasPrefix(set_cookie[0], "TOKEN=") {
				// Probably not Unifi
				return
			}

			ret = append(ret, url)
		}(iter)
	}

	wg.Wait()

	return ret, nil
}

func getLink() (netlink.Link, error) {
	links, err := getLinks()
	if err != nil {
		return nil, err
	}

	if len(links) == 0 {
		return nil, fmt.Errorf("no links found (TODO)")
	}

	if len(links) > 1 {
		return nil, fmt.Errorf("more than one link (TODO)")
	}

	return links[0], nil
}

func getLinks() ([]netlink.Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}

	ret := []netlink.Link{}

	for _, link := range links {
		if link.Attrs().Flags & net.FlagUp == 0 {
			// Link is down
			continue
		}

		if link.Attrs().Flags & net.FlagLoopback != 0 {
			// Link is loopback
			continue
		}

		if link.Attrs().EncapType != "ether" {
			// Not ethernet
			continue
		}

		ret = append(ret, link)
	}

	return ret, nil
}
