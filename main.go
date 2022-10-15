package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"time"
	"unsafe"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type IfInfomsg struct {
	Family uint8
	_      uint8
	Type   uint16
	Index  int32
	Flags  uint32
	Change uint32
}

func (msg *IfInfomsg) Serialize() []byte {
	return (*(*[unix.SizeofIfInfomsg]byte)(unsafe.Pointer(msg)))[:]
}

type IfAddrmsg struct {
	Family    uint8
	Prefixlen uint8
	Flags     uint8
	Scope     uint8
	Index     uint32
}

func (msg *IfAddrmsg) Serialize() []byte {
	return (*(*[unix.SizeofIfAddrmsg]byte)(unsafe.Pointer(msg)))[:]
}

func addWg(c *netlink.Conn, name string, address net.IPNet, mtu int) error {

	infomsg := IfInfomsg{
		Family: unix.AF_UNSPEC,
		Change: unix.IFF_UP | unix.IFF_LOWER_UP,
		Flags:  unix.IFF_UP | unix.IFF_LOWER_UP,
	}

	ne := netlink.NewAttributeEncoder()
	ne.Int32(unix.IFLA_MTU, int32(mtu))
	ne.String(unix.IFLA_IFNAME, name)

	ne.Nested(unix.IFLA_LINKINFO, func(nae *netlink.AttributeEncoder) error {
		nae.String(unix.IFLA_INFO_KIND, unix.WG_GENL_NAME)
		return nil
	})

	req := netlink.Message{
		Header: netlink.Header{
			Type:  unix.RTM_NEWLINK,
			Flags: netlink.Request | netlink.Create | netlink.Excl | netlink.Acknowledge,
		},
	}

	req.Data = infomsg.Serialize()

	msg, err := ne.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode: %v", err)
	}

	req.Data = append(req.Data, msg...)

	resp, err := c.Execute(req)
	if err != nil {
		return fmt.Errorf("failed to execute message: %v", err)
	}

	switch resp[0].Header.Type {
	case netlink.Error:
		errCode := binary.LittleEndian.Uint32(resp[0].Data)
		if errCode != 0 {
			fmt.Println("Netlink reported error: ", errCode)
			return errors.New("got netlink error: " + fmt.Sprintf("%d", errCode))
		}
	}

	return setIp(c, name, address)
}

func setIp(c *netlink.Conn, name string, address net.IPNet) error {

	req := netlink.Message{
		Header: netlink.Header{
			Type:  unix.RTM_NEWADDR,
			Flags: netlink.Request | netlink.Acknowledge,
		},
	}

	iface, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("lookup network iface %q: %s", name, err)
	}

	addrMsg := IfAddrmsg{
		Family: unix.AF_INET,
		Index:  uint32(iface.Index),
	}

	preflen, _ := address.Mask.Size()
	addrMsg.Prefixlen = uint8(preflen)

	req.Data = addrMsg.Serialize()

	ne := netlink.NewAttributeEncoder()
	ne.Bytes(unix.IFA_LOCAL, address.IP[:4])

	msg, err := ne.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode af: %v", err)
	}

	req.Data = append(req.Data, msg...)

	resp, err := c.Execute(req)
	if err != nil {
		return fmt.Errorf("failed to execute message: %v", err)
	}

	switch resp[0].Header.Type {
	case netlink.Error:
		errCode := binary.LittleEndian.Uint32(resp[0].Data)
		if errCode != 0 {
			fmt.Println("Netlink reported error: ", errCode)
			return errors.New("got netlink error: " + fmt.Sprintf("%d", errCode))
		}
	}

	return nil
}

func delWg(c *netlink.Conn, name string) error {
	infomsg := IfInfomsg{
		Family: unix.AF_UNSPEC,
		Change: unix.IFF_UP | unix.IFF_LOWER_UP,
		Flags:  unix.IFF_UP | unix.IFF_LOWER_UP,
	}

	ne := netlink.NewAttributeEncoder()
	ne.String(unix.IFLA_IFNAME, name)

	ne.Nested(unix.IFLA_LINKINFO, func(nae *netlink.AttributeEncoder) error {
		nae.String(unix.IFLA_INFO_KIND, unix.WG_GENL_NAME)
		return nil
	})

	req := netlink.Message{
		Header: netlink.Header{
			Type:  unix.RTM_DELLINK,
			Flags: netlink.Request | netlink.Acknowledge,
		},
	}

	req.Data = infomsg.Serialize()

	msg, err := ne.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode: %v", err)
	}

	req.Data = append(req.Data, msg...)

	resp, err := c.Execute(req)
	if err != nil {
		return fmt.Errorf("failed to execute message: %v", err)
	}

	switch resp[0].Header.Type {
	case netlink.Error:
		errCode := binary.LittleEndian.Uint32(resp[0].Data)
		if errCode != 0 {
			fmt.Println("Netlink reported error: ", errCode)
			return errors.New("got netlink error: " + fmt.Sprintf("%d", errCode))
		}
	}

	return nil
}

func main() {

	conn, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	const devName = "wg2"
	fmt.Print("Creating wireguard device...")

	ip, n, _ := net.ParseCIDR("192.168.2.1/24")
	n.IP = ip.To4()
	if err := addWg(conn, devName, *n, 1420); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Done!")

	fmt.Print("Connecting to wireguard control...")
	ctrl, err := wgctrl.New()
	if err != nil {
		fmt.Printf("cannot start wireguard control %v\n", err)
		return
	}
	fmt.Println("Done!")

	fmt.Print("Using wireguard control to set configuration...")
	pk, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		fmt.Printf("cannot generate key %v\n", err)
		return
	}

	port := 3333

	c := wgtypes.Config{
		PrivateKey: &pk,
		ListenPort: &port,
	}

	err = ctrl.ConfigureDevice(devName, c)
	if err != nil {
		fmt.Printf("cannot configure wireguard device %v\n", err)
		return
	}
	fmt.Println("Done!")

	fmt.Print("Waiting 15 seconds...")
	time.Sleep(15 * time.Second)
	fmt.Println("Done!")

	fmt.Print("Deleting wireguard device...")
	if err := delWg(conn, devName); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Done!")
}
