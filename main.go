package main

import (
    "fmt"
    "log"
    "net"
    "os"

    "github.com/google/nftables"
    "github.com/google/nftables/expr"
)

type NFTables interface {
    CreateBlocklist() error
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
    _, ipnet, err := net.ParseCIDR(network)
    if err == nil {
	return ipnet, nil
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
    _, err := parseNetwork(network)
    if err != nil {
	return err
    }
    return fw.handler.AddNetwork(network)
}

func (fw *Firewall) RemoveNetwork(network string) error {
    _, err := parseNetwork(network)
    if err != nil {
	return err
    }
    return fw.handler.RemoveNetwork(network)
}

func (fw *Firewall) ListNetworks() ([]string, error) {
    return fw.handler.ListNetworks()
}

type RealNFT struct {
    tableName string
    chainName string
    setName   string
}

func NewRealNFT() *RealNFT {
    return &RealNFT{
	tableName: "myfirewall",
	chainName: "input",
	setName:   "blocked_nets",
    }
}

func (r *RealNFT) CreateBlocklist() error {
    conn := &nftables.Conn{}

    table := conn.AddTable(&nftables.Table{
	Family: nftables.TableFamilyIPv4,
	Name:   r.tableName,
    })

    conn.AddChain(&nftables.Chain{
	Name:     r.chainName,
	Table:    table,
	Type:     nftables.ChainTypeFilter,
	Hooknum:  nftables.ChainHookInput,
	Priority: nftables.ChainPriorityFilter,
    })

    set := &nftables.Set{
	Name:     r.setName,
	Table:    table,
	KeyType:  nftables.TypeIPAddr,
	Interval: true,
    }

    if err := conn.AddSet(set, []nftables.SetElement{}); err != nil {
	return err
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
	&expr.Verdict{Kind: expr.VerdictDrop},
    }

    conn.AddRule(&nftables.Rule{
	Table: table,
	Chain: &nftables.Chain{Name: r.chainName},
	Exprs: exprs,
    })

    return conn.Flush()
}

func (r *RealNFT) AddNetwork(network string) error {
    ipnet, err := parseNetwork(network)
    if err != nil {
	return err
    }

    conn := &nftables.Conn{}
    table := conn.AddTable(&nftables.Table{
	Family: nftables.TableFamilyIPv4,
	Name:   r.tableName,
    })
    set, err := conn.GetSetByName(table, r.setName)
    if err != nil {
	return err
    }

    element := nftables.SetElement{
	Key:         ipnet.IP,
	Mask:        ipnet.Mask,
    }

    return conn.SetAddElements(set, []nftables.SetElement{element})
}

func (r *RealNFT) RemoveNetwork(network string) error {
    ipnet, err := parseNetwork(network)
    if err != nil {
	return err
    }

    conn := &nftables.Conn{}
    table := conn.AddTable(&nftables.Table{
	Family: nftables.TableFamilyIPv4,
	Name:   r.tableName,
    })
    set, err := conn.GetSetByName(table, r.setName)
    if err != nil {
	return err
    }

    element := nftables.SetElement{
	Key:         ipnet.IP,
	Mask:        ipnet.Mask,
    }

    return conn.SetDeleteElements(set, []nftables.SetElement{element})
}

func (r *RealNFT) ListNetworks() ([]string, error) {
    conn := &nftables.Conn{}
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

    var networks []string
    for _, elem := range elements {
	ipnet := &net.IPNet{
	    IP:   elem.Key,
	    Mask: elem.Mask,
	}
	networks = append(networks, ipnet.String())
    }
    return networks, nil
}

func main() {
    fw := NewFirewall(NewRealNFT())

    if len(os.Args) < 2 {
	fmt.Println("Usage:")
	fmt.Println("  create - create firewall rules")
	fmt.Println("  add <IP/CIDR> - add network to blocklist")
	fmt.Println("  del <IP/CIDR> - remove network from blocklist")
	fmt.Println("  list - show blocked networks")
	os.Exit(1)
    }

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
