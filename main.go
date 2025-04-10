package main

import (
    "fmt"
    "log"
    "net"
    "os"

    "github.com/google/nftables"
    "github.com/google/nftables/expr"
)

// Интерфейс для работы с nftables
type NFTables interface {
    CreateBlocklist() error
    AddIP(ip net.IP) error
    RemoveIP(ip net.IP) error
    ListIPs() ([]net.IP, error)
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

func (fw *Firewall) AddIP(ipStr string) error {
    ip := net.ParseIP(ipStr)
    if ip == nil || ip.To4() == nil {
	return fmt.Errorf("invalid IPv4 address")
    }
    return fw.handler.AddIP(ip)
}

func (fw *Firewall) RemoveIP(ipStr string) error {
    ip := net.ParseIP(ipStr)
    if ip == nil || ip.To4() == nil {
	return fmt.Errorf("invalid IPv4 address")
    }
    return fw.handler.RemoveIP(ip)
}

func (fw *Firewall) ListIPs() ([]string, error) {
    ips, err := fw.handler.ListIPs()
    if err != nil {
	return nil, err
    }
    
    result := make([]string, len(ips))
    for i, ip := range ips {
	result[i] = ip.String()
    }
    return result, nil
}

// Реальная реализация для работы с nftables
type RealNFT struct {
    tableName string
    chainName string
    setName   string
}

func NewRealNFT() *RealNFT {
    return &RealNFT{
	tableName: "myfirewall",
	chainName: "input",
	setName:   "blocked_ips",
    }
}

func (r *RealNFT) CreateBlocklist() error {
    conn := nftables.Conn{}

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
	Name:    r.setName,
	Table:   table,
	KeyType: nftables.TypeIPAddr,
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
	    SetName:       r.setName,
	    SetID:         set.ID,
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

func (r *RealNFT) AddIP(ip net.IP) error {
    conn := nftables.Conn{}
    table := conn.AddTable(&nftables.Table{
	Family: nftables.TableFamilyIPv4,
	Name:   r.tableName,
    })
    set, err := conn.GetSetByName(table, r.setName)
    if err != nil {
	return err
    }
    return conn.SetAddElements(set, []nftables.SetElement{{Key: ip.To4()}})
}

func (r *RealNFT) RemoveIP(ip net.IP) error {
    conn := nftables.Conn{}
    table := conn.AddTable(&nftables.Table{
	Family: nftables.TableFamilyIPv4,
	Name:   r.tableName,
    })
    set, err := conn.GetSetByName(table, r.setName)
    if err != nil {
	return err
    }
    return conn.SetDeleteElements(set, []nftables.SetElement{{Key: ip.To4()}})
}

func (r *RealNFT) ListIPs() ([]net.IP, error) {
    conn := nftables.Conn{}
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

    ips := make([]net.IP, len(elements))
    for i, e := range elements {
	ips[i] = e.Key
    }
    return ips, nil
}

func main() {
    fw := NewFirewall(NewRealNFT())

    if len(os.Args) < 2 {
	fmt.Println("Usage:")
	fmt.Println("  create - create firewall rules")
	fmt.Println("  add <IP> - add IP to blocklist")
	fmt.Println("  del <IP> - remove IP from blocklist")
	fmt.Println("  list - show blocked IPs")
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
	    log.Fatal("IP address required")
	}
	if err := fw.AddIP(os.Args[2]); err != nil {
	    log.Fatal(err)
	}
	fmt.Println("IP added")
    case "del":
	if len(os.Args) < 3 {
	    log.Fatal("IP address required")
	}
	if err := fw.RemoveIP(os.Args[2]); err != nil {
	    log.Fatal(err)
	}
	fmt.Println("IP removed")
    case "list":
	ips, err := fw.ListIPs()
	if err != nil {
	    log.Fatal(err)
	}
	fmt.Println("Blocked IPs:")
	for _, ip := range ips {
	    fmt.Println(ip)
	}
    default:
	log.Fatal("Unknown command")
    }
}
