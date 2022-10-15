package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"unsafe"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
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

func main() {

	conn, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	infomsg := IfInfomsg{
		Family: unix.AF_UNSPEC,
		Change: unix.IFF_UP | unix.IFF_LOWER_UP,
		Flags:  unix.IFF_UP | unix.IFF_LOWER_UP,
	}

	ne := netlink.NewAttributeEncoder()
	ne.Int32(unix.IFLA_MTU, 1420)
	ne.String(unix.IFLA_IFNAME, "wg3")

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
		log.Fatal("failed to encode: ", err)
	}

	req.Data = append(req.Data, msg...)

	resp, err := conn.Execute(req)
	if err != nil {
		log.Fatal(err)
	}

	switch resp[0].Header.Type {
	case netlink.Error:
		errCode := binary.LittleEndian.Uint32(resp[0].Data)
		if errCode != 0 {
			fmt.Println("Netlink reported error: ", errCode)
			return
		}
	}

	fmt.Println("All goods!")

	conn.Receive()

}
