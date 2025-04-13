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
	Create(accept bool) error
	ModifyIP(accept, add bool, networks []string) error
	Add(accept bool, networks []string) error
	Remove(accept bool, networks []string) error
	List(accept bool) ([]string, error)
	Destroy() error
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

func (fw *Firewall) Create() error {
	if err := fw.handler.Create(true); err != nil {
		return err
	}

	return fw.handler.Create(false)
}

func (fw *Firewall) ModifyIP(accept, add bool, networks []string) error {
	return fw.handler.ModifyIP(accept, add, networks)
}

func (fw *Firewall) Add(accept bool, networks []string) error {
	return fw.handler.Add(accept, networks)
}

func (fw *Firewall) Remove(accept bool, networks []string) error {
	return fw.handler.Remove(accept, networks)
}

func (fw *Firewall) List(accept bool) ([]string, error) {
	return fw.handler.List(accept)
}

func (fw *Firewall) Destroy() error {
	return fw.handler.Destroy()
}
