package main

import (
    "fmt"
    "log"
    "net"
    "os"

    "github.com/google/nftables"
    "github.com/google/nftables/expr"
)

const (
    tableName = "myfirewall"
    chainName = "input"
    setName   = "blocked_ips"
)

var nftConn NFT = &nftables.Conn{}

func createBlocklist() {
    conn := nftConn

    // Создание таблицы
    table := conn.AddTable(&nftables.Table{
	Family: nftables.TableFamilyIPv4,
	Name:   tableName,
    })

    // Создание цепочки
    conn.AddChain(&nftables.Chain{
	Name:     chainName,
	Table:    table,
	Type:     nftables.ChainTypeFilter,
	Hooknum:  nftables.ChainHookInput,
	Priority: nftables.ChainPriorityFilter,
    })

    // Создание множества для IP-адресов
    set := &nftables.Set{
	Name:    setName,
	Table:   table,
	KeyType: nftables.TypeIPAddr,
    }
    if err := conn.AddSet(set, []nftables.SetElement{}); err != nil {
	log.Fatalf("Error creating set: %v", err)
    }

    // Добавление правила для блокировки
    exprs := []expr.Any{
	// Загрузка исходного IP-адреса
	&expr.Payload{
	    DestRegister: 1,
	    Base:         expr.PayloadBaseNetworkHeader,
	    Offset:       12,
	    Len:          4,
	},
	// Проверка наличия в множестве
	&expr.Lookup{
	    SourceRegister: 1,
	    SetName:       setName,
	    SetID:         set.ID,
	},
	// Блокировка пакета
	&expr.Verdict{
	    Kind: expr.VerdictDrop,
	},
    }

    conn.AddRule(&nftables.Rule{
	Table: table,
	Chain: &nftables.Chain{Name: chainName},
	Exprs: exprs,
    })

    if err := conn.Flush(); err != nil {
	log.Fatalf("Error applying rules: %v", err)
    }

    fmt.Println("Блокирующие правила успешно созданы")
}

func modifyIP(ip string, add bool) {
    conn := nftConn

    table := conn.AddTable(&nftables.Table{
	Family: nftables.TableFamilyIPv4,
	Name:   tableName,
    })

    set, err := conn.GetSetByName(table, setName)
    if err != nil {
	log.Fatalf("Error getting set: %v", err)
    }

    parsedIP := net.ParseIP(ip)
    if parsedIP == nil || parsedIP.To4() == nil {
	log.Fatalf("Invalid IPv4 address: %s", ip)
    }

    element := nftables.SetElement{Key: parsedIP.To4()}

    var op func(*nftables.Set, []nftables.SetElement) error
    if add {
	op = conn.SetAddElements
    } else {
	op = conn.SetDeleteElements
    }

    if err := op(set, []nftables.SetElement{element}); err != nil {
	log.Fatalf("Error modifying set: %v", err)
    }

    if err := conn.Flush(); err != nil {
	log.Fatalf("Error applying changes: %v", err)
    }

    action := "добавлен"
    if !add {
	action = "удалён"
    }
    fmt.Printf("IP %s успешно %s\n", ip, action)
}

func listBlockedIPs() {
    conn := nftConn

    table := conn.AddTable(&nftables.Table{
	Family: nftables.TableFamilyIPv4,
	Name:   tableName,
    })

    set, err := conn.GetSetByName(table, setName)
    if err != nil {
	log.Fatalf("Error getting set: %v", err)
    }

    elements, err := conn.GetSetElements(set)
    if err != nil {
	log.Fatalf("Error getting elements: %v", err)
    }

    fmt.Println("Заблокированные IP-адреса:")
    for _, elem := range elements {
	ip := net.IP(elem.Key)
	fmt.Println(ip)
    }
}

func main() {
    if len(os.Args) < 2 {
	fmt.Println("Использование:")
	fmt.Println("  create - создать таблицу и правила")
	fmt.Println("  add <IP> - добавить IP в блокировку")
	fmt.Println("  del <IP> - удалить IP из блокировки")
	fmt.Println("  list - показать заблокированные IP")
	os.Exit(1)
    }

    cmd := os.Args[1]
    switch cmd {
    case "create":
	createBlocklist()
    case "add":
	if len(os.Args) < 3 {
	    log.Fatal("Требуется указать IP-адрес")
	}
	modifyIP(os.Args[2], true)
    case "del":
	if len(os.Args) < 3 {
	    log.Fatal("Требуется указать IP-адрес")
	}
	modifyIP(os.Args[2], false)
    case "list":
	listBlockedIPs()
    default:
	log.Fatal("Неизвестная команда")
    }
}
