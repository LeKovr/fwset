package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

type NFTables interface {
	CreateBlocklist() error
	ModifyIP(network string, add bool) error
	AddNetwork(network string) error
	RemoveNetwork(network string) error
	ListNetworks() ([]string, error)
}

type Firewall struct {
	handler NFTables
}

func NewFirewall(handler NFTables) *Firewall {
	return &Firewall{handler: handler}
}

func (fw *Firewall) CreateBlocklist() error {
	return fw.handler.CreateBlocklist()
}

func parseNetwork(network string) (*net.IPNet, error) {
	if strings.Contains(network, "/") {
		_, ipnet, err := net.ParseCIDR(network)
		return ipnet, err
	}

	ip := net.ParseIP(network)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP/CIDR")
	}

	if ip.To4() != nil {
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}

func (fw *Firewall) AddNetwork(network string) error {
	return fw.handler.AddNetwork(network)
}

func (fw *Firewall) RemoveNetwork(network string) error {
	return fw.handler.RemoveNetwork(network)
}

func (fw *Firewall) ListNetworks() ([]string, error) {
	return fw.handler.ListNetworks()
}

type RealNFT struct {
	tableName string
	chainName string
	setName   string
	conn      NFT
	isAccept  bool
}

func NewRealNFT() (*RealNFT, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, err
	}
	return &RealNFT{
		tableName: "myfirewall",
		chainName: "input",
		setName:   "blocked_nets",
		conn:      conn, //&nftables.Conn{},
	}, nil
}

func (r *RealNFT) CreateBlocklist() error {
	conn := r.conn

	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   r.tableName,
	})

	conn.AddChain(&nftables.Chain{
		Name:     r.chainName,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput, // TODO: проверить ChainHookIngress
		Priority: nftables.ChainPriorityFilter,
	})

	set := &nftables.Set{
		Name:     r.setName,
		Table:    table,
		KeyType:  nftables.TypeIPAddr,
		Interval: true,
		// AutoMerge: true, // TODO: найти кейс, где это нужно
	}
	// See https://github.com/google/nftables/issues/247#issuecomment-1813787205
	elements := []nftables.SetElement{
		{
			Key:         []byte{0x00, 0x00, 0x00, 0x00},
			IntervalEnd: true,
		},
	}
	if err := conn.AddSet(set, elements); err != nil {
		return err
	}
	kind := expr.VerdictDrop
	if r.isAccept {
		kind = expr.VerdictAccept
	}

	exprs := []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       12,
			Len:          4,
		},
		&expr.Lookup{
			SourceRegister: 1,
			SetName:        r.setName,
			SetID:          set.ID,
		},
		/*
		   TODO: Что это добавит?
		           &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		           &expr.Cmp{
		                   Op:       expr.CmpOpEq,
		                   Register: 1,
		                   Data:     []byte{unix.IPPROTO_TCP},
		           },
		*/
		&expr.Counter{}, // TODO: вынести в config
		&expr.Log{},     // TODO: вынести в config
		&expr.Verdict{Kind: kind},
	}

	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: &nftables.Chain{Name: r.chainName},
		Exprs: exprs,
	})

	return conn.Flush()
}

// Функция для преобразования CIDR в диапазон адресов
func cidrToRange(network string) (net.IP, net.IP, error) {
	var firstIP, lastIP net.IP
	if strings.Contains(network, "-") {
		ips := strings.Split(network, "-")
		firstIP = net.ParseIP(ips[0])
		if firstIP == nil {
			return nil, nil, fmt.Errorf("invalid First IP")
		}
		lastIP = net.ParseIP(ips[1])
		if lastIP == nil {
			return nil, nil, fmt.Errorf("invalid Last IP")
		}
	} else {
		ipnet, err := parseNetwork(network) // добавим маску, если не было
		if err != nil {
			return nil, nil, err
		}
		firstIP, lastIP, err = nftables.NetFirstAndLastIP(ipnet.String())
		if err != nil {
			return nil, nil, err
		}
	}
	return firstIP, lastIP, nil
}

func (r *RealNFT) ModifyIP(network string, add bool) error {
	firstIP, lastIP, err := cidrToRange(network)
	if err != nil {
		return err
	}
	lastIP = nextIP(lastIP) // для диапазона нужен следующий за крайним ip

	conn := r.conn
	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   r.tableName,
	})
	set, err := conn.GetSetByName(table, r.setName)
	if err != nil {
		return err
	}

	elements := []nftables.SetElement{
		{Key: []byte(firstIP.To4())},
		{Key: lastIP.To4(), IntervalEnd: true},
	}

	if add {
		if err := conn.SetAddElements(set, elements); err != nil {
			return err
		}
	} else {
		if err := conn.SetDeleteElements(set, elements); err != nil {
			return err
		}
	}

	return conn.Flush()
}

func (r *RealNFT) AddNetwork(network string) error {
	return r.ModifyIP(network, true)
}

func (r *RealNFT) RemoveNetwork(network string) error {
	return r.ModifyIP(network, false)
}

func (r *RealNFT) ListNetworks() ([]string, error) {
	conn := r.conn
	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   r.tableName,
	})
	set, err := conn.GetSetByName(table, r.setName)
	if err != nil {
		return nil, err
	}

	elements, err := conn.GetSetElements(set)
	if err != nil {
		return nil, err
	}

	var end net.IP
	var networks []string
	for _, elem := range elements {
		// Преобразование обратно в CIDR
		if elem.IntervalEnd {
			end = net.IP(elem.Key)
			// следний элемент - 0.0.0.0 с IntervalEnd, будетнеявно проигнорирован
			continue
		}
		start := net.IP(elem.Key)
		end = previousIP(end)
		//fmt.Printf("%s .. %s\n", start, end)

		nets, err := IpRangeToCIDR(nil, start.String(), end.String())
		if err != nil {
			// TODO: log err
			continue
		}
		if len(nets) > 1 {
			// для нас диапазон будет лучше
			nets = []string{fmt.Sprintf("%s-%s", start, end)}
		}
		networks = append(networks, nets...)
	}

	return networks, nil
}

func main() {

	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  create - create firewall rules")
		fmt.Println("  add <IP/CIDR> - add network to blocklist")
		fmt.Println("  del <IP/CIDR> - remove network from blocklist")
		fmt.Println("  list - show blocked networks")
		os.Exit(1)
	}
	nft, err := NewRealNFT()
	if err != nil {
		log.Fatal(err)
	}
	fw := NewFirewall(nft)

	cmd := os.Args[1]
	switch cmd {
	case "create":
		if err := fw.CreateBlocklist(); err != nil {
			log.Fatal(err)
		}
		fmt.Println("Blocklist created")
	case "add":
		if len(os.Args) < 3 {
			log.Fatal("Network address required")
		}
		if err := fw.AddNetwork(os.Args[2]); err != nil {
			log.Fatal(err)
		}
		fmt.Println("Network added")
	case "del":
		if len(os.Args) < 3 {
			log.Fatal("Network address required")
		}
		if err := fw.RemoveNetwork(os.Args[2]); err != nil {
			log.Fatal(err)
		}
		fmt.Println("Network removed")
	case "list":
		networks, err := fw.ListNetworks()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Blocked networks:")
		for _, network := range networks {
			fmt.Println(network)
		}
	default:
		log.Fatal("Unknown command")
	}
}

func nextIP(ip net.IP) net.IP {
	/*      ip := net.ParseIP(ipStr)
	        if ip == nil {
	                return "", fmt.Errorf("invalid IP address: %s", ipStr)
	        }
	*/
	// Определяем версию IP и нормализуем представление
	var bytes []byte
	if v4 := ip.To4(); v4 != nil {
		bytes = make([]byte, len(v4))
		copy(bytes, v4)
	} else {
		v6 := ip.To16()
		bytes = make([]byte, len(v6))
		copy(bytes, v6)
	}

	// Инкрементируем IP-адрес
	carry := 1
	for i := len(bytes) - 1; i >= 0; i-- {
		sum := int(bytes[i]) + carry
		bytes[i] = byte(sum % 256)
		carry = sum / 256
		if carry == 0 {
			break
		}
	}

	if carry != 0 {
		// return nil, fmt.Errorf("IP address overflow")
		return nil
	}

	return net.IP(bytes)
}

func previousIP(ip net.IP) net.IP {
	// Определяем версию IP и нормализуем представление
	var bytes []byte
	if v4 := ip.To4(); v4 != nil {
		bytes = make([]byte, len(v4))
		copy(bytes, v4)
	} else {
		v6 := ip.To16()
		bytes = make([]byte, len(v6))
		copy(bytes, v6)
	}

	// Декрементируем IP-адрес
	borrow := 1
	for i := len(bytes) - 1; i >= 0; i-- {
		current := int(bytes[i]) - borrow
		if current >= 0 {
			bytes[i] = byte(current)
			borrow = 0
			break
		}
		// Обрабатываем заем
		bytes[i] = 255
		borrow = 1
	}

	// Проверяем переполнение (все байты стали 255)
	if borrow != 0 {

		//return "", fmt.Errorf("IP address underflow")
		return nil
	}
	return net.IP(bytes)
}
