package fwset

import (
	"errors"

	"github.com/LeKovr/fwset/config"
	"github.com/LeKovr/fwset/nftables"
)

// Config содержит тип и стандартные настройки фаервола.
type Config struct {
	FW string `choice:"nft" choice:"ipset" default:"nft" description:"Firewall type" env:"FW" long:"fw"`
	config.Config
}

// NFTables описывает общий для фаерволов интерфейс.
type NFTables interface {
	CreateBlocklist() error
	ModifyIP(networks []string, add bool) error
	AddNetwork(networks []string) error
	RemoveNetwork(networks []string) error
	ListNetworks() ([]string, error)
}

// Firewall содержит методы, которые проксируются в фаервол.
type Firewall struct {
	config  Config
	handler NFTables
}

// ErrNotImplemented возвращается при попытке инициализировать нереализованный фаервол.
var ErrNotImplemented = errors.New("not implemented")

// New возвращает экземпляр фаервола.
func New(cfg Config) (*Firewall, error) {
	if cfg.FW != "nft" {
		return nil, ErrNotImplemented
	}

	handler, err := nftables.NewRealNFT(cfg.Config)
	if err != nil {
		return nil, err
	}

	return &Firewall{
		config:  cfg,
		handler: handler,
	}, nil
}

func (fw *Firewall) CreateBlocklist() error {
	return fw.handler.CreateBlocklist()
}

func (fw *Firewall) ModifyIP(networks []string, add bool) error {
	if add {
		return fw.AddNetwork(networks)
	}

	return fw.RemoveNetwork(networks)
}

func (fw *Firewall) AddNetwork(networks []string) error {
	return fw.handler.AddNetwork(networks)
}

func (fw *Firewall) RemoveNetwork(networks []string) error {
	return fw.handler.RemoveNetwork(networks)
}

func (fw *Firewall) ListNetworks() ([]string, error) {
	return fw.handler.ListNetworks()
}
