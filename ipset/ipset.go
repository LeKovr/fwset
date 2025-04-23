package ipset

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/LeKovr/fwset/config"
	"github.com/LeKovr/fwset/utils"

	"github.com/lrh3321/ipset-go"
)

type Config struct {
	config.Config
}

type FireWall struct {
	config config.Config
	conn   IPS
}

func New(cfg config.Config) (*FireWall, error) {
	conn, err := ipset.NewHandle()
	if err != nil {
		return nil, err
	}

	return &FireWall{
		config: cfg,
		conn:   conn,
	}, nil
}

func (fw *FireWall) setName(is_accept bool) string {
	if is_accept {
		return fw.config.SetNameAccept
	}
	return fw.config.SetNameDrop

}

func (fw *FireWall) Create(accept bool) error {

	// iptables -I INPUT -m set --match-set fedeban-ip-on src -j ACCEPT
	// iptables -I INPUT -m set --match-set fedeban-net-off src -j DROP
	conn := fw.conn
	name := fw.setName(accept)

	err := conn.Create(name, ipset.TypeHashNet, ipset.CreateOptions{
		Replace: true,
	}) // ipset create bad_nets_n hash:net hashsize 4096 maxelem 262144

	return err
}

func (fw *FireWall) Destroy() error {
	conn := fw.conn
	if err := conn.Destroy(fw.config.SetNameAccept); err != nil {
		return err
	}
	return conn.Destroy(fw.config.SetNameDrop)
}

func (fw *FireWall) Modify(accept, add bool, networks []string) error {
	conn := fw.conn
	name := fw.setName(accept)
	for _, network := range networks {
		entry, err := CIDRToEntry(network)
		if err != nil {
			return err
		}
		//fmt.Printf("Add: %+v\n", entry)
		// Equivalent to: `ipset add hash01 10.0.0.1`
		//err = ipset.Add(setname, &ipset.Entry{IP: net.IPv4(10, 0, 0, 1).To4()})
		if add {
			err = conn.Add(name, entry)
		} else {
			err = conn.Del(name, entry)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *FireWall) Add(accept bool, networks []string) error {
	return r.Modify(accept, true, networks)
}

func (r *FireWall) Remove(accept bool, networks []string) error {
	return r.Modify(accept, false, networks)
}

func (fw *FireWall) List(accept bool) ([]string, error) {
	conn := fw.conn
	// List the set.
	set, err := conn.List(fw.setName(accept))
	if err != nil {
		return nil, err
	}
	rv := make([]string, len(set.Entries))
	for i, e := range set.Entries {
		network := e.IP.String()
		if e.CIDR != 32 {
			network = fmt.Sprintf("%s/%d", network, e.CIDR)
		}
		rv[i] = network
	}
	return rv, nil
}

// &ipset.Entry{IP: net.IPv4(176, 123, 165, 0).To4()}

func CIDRToEntry(network string) (*ipset.Entry, error) {

	if strings.Contains(network, "-") {
		// для этого нужен отдельный set типа hash:net,net
		return nil, fmt.Errorf("IP range not implemented")
	}
	ipnet, err := utils.ParseNetwork(network) // добавим маску, если не было
	if err != nil {
		return nil, err
	}
	parts := strings.Split(ipnet.String(), "/")
	m, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, err
	}

	return &ipset.Entry{IP: ipnet.IP.To4(), CIDR: uint8(m), Replace: true}, nil

}
