package nftables

import (
	"fmt"
	"net"

	"github.com/LeKovr/fwset/config"
	"github.com/LeKovr/fwset/utils"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

type Config struct {
	config.Config
}

type RealNFT struct {
	config config.Config
	conn   NFT
}

func NewRealNFT(cfg config.Config) (*RealNFT, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, err
	}

	return &RealNFT{
		config: cfg,
		conn:   conn, //&nftables.Conn{},
	}, nil
}

func (r *RealNFT) CreateBlocklist() error {
	conn := r.conn

	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   r.config.TableName,
	})

	conn.AddChain(&nftables.Chain{
		Name:     r.config.ChainName,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput, // TODO: проверить ChainHookIngress
		Priority: nftables.ChainPriorityFilter,
	})

	set := &nftables.Set{
		Name:     r.config.SetName,
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
	if r.config.IsAccept {
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
			SetName:        r.config.SetName,
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
		Chain: &nftables.Chain{Name: r.config.ChainName},
		Exprs: exprs,
	})

	return conn.Flush()
}

func (r *RealNFT) ModifyIP(networks []string, add bool) error {
	conn := r.conn
	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   r.config.TableName,
	})

	set, err := conn.GetSetByName(table, r.config.SetName)
	if err != nil {
		return err
	}

	for _, network := range networks {
		firstIP, lastIP, err := utils.CIDRToRange(network)
		if err != nil {
			return err
		}

		lastIP = utils.NextIP(lastIP) // для диапазона нужен следующий за крайним ip

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
	}

	return conn.Flush()
}

func (r *RealNFT) AddNetwork(networks []string) error {
	return r.ModifyIP(networks, true)
}

func (r *RealNFT) RemoveNetwork(networks []string) error {
	return r.ModifyIP(networks, false)
}

func (r *RealNFT) ListNetworks() ([]string, error) {
	conn := r.conn
	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   r.config.TableName,
	})

	set, err := conn.GetSetByName(table, r.config.SetName)
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
			// последний элемент - 0.0.0.0 с IntervalEnd, будетнеявно проигнорирован
			continue
		}

		start := net.IP(elem.Key)
		end = utils.PreviousIP(end)
		// fmt.Printf("%s .. %s\n", start, end)

		nets, err := utils.IPRangeToCIDR(nil, start.String(), end.String())
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
