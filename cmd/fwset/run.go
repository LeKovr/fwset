package main

// See also: https://blog.logrocket.com/guide-to-grpc-gateway/

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/LeKovr/go-kit/config"
	"github.com/LeKovr/go-kit/slogger"
	"github.com/LeKovr/go-kit/ver"

	"github.com/LeKovr/fwset"
)

// Config holds all config vars.
type Config struct {
	Command struct {
		Name string   `choice:"create"                                            choice:"list"            choice:"add" choice:"del" choice:"destroy" description:"Команда"        positional-arg-name:"COMMAND"` //nolint:staticcheck
		IPs  []string `description:"IP адрес (для команд add, del)"               positional-arg-name:"IP"`
	} `positional-args:"true"`
	IsAccept bool `description:"Use Accept instead of Drop" env:"ACCEPT" long:"accept"`

	fwset.Config
	Logger slogger.Config `env-namespace:"LOG" group:"Logging Options" namespace:"log"`

	config.EnableShowVersion
	config.EnableConfigDefGen
	config.EnableConfigDump
}

const (
	application = "fwset"
)

var (
	// App version, actual value will be set at build time.
	version = "0.0-dev"

	// Repository address, actual value will be set at build time.
	repo = "repo.git"

	ErrNoRequiredIPs  = errors.New("network address required")
	ErrUnknownCommand = errors.New("unknown command")
)

// Run app and exit via given exitFunc.
func Run(_ context.Context, exitFunc func(code int)) {
	config.SetApplicationVersion(application, version)
	// Load config
	var cfg Config
	err := config.Open(&cfg)

	defer func() {
		if r := recover(); r != nil {
			slog.Error("Recovered panic", "err", r)
		}

		config.Close(err, exitFunc)
	}()

	if err != nil {
		return
	}

	err = slogger.Setup(cfg.Logger, nil)
	if err != nil {
		return
	}

	fmt.Println(application, version)

	go ver.Check(repo, version)

	var fw *fwset.Firewall

	fw, err = fwset.New(cfg.Config)
	if err != nil {
		return
	}

	err = run(cfg, fw)
}

func run(cfg Config, fw *fwset.Firewall) error {
	var err error

	switch cfg.Command.Name {
	case "create":
		if err = fw.Create(); err == nil {
			fmt.Println("Sets created")
		}

	case "destroy":
		if err = fw.Destroy(); err == nil {
			fmt.Println("Sets destroyed")
		}

	case "add":
		if len(cfg.Command.IPs) < 1 {
			return ErrNoRequiredIPs
		}

		if err = fw.Add(cfg.IsAccept, cfg.Command.IPs); err != nil {
			return err
		}

		fmt.Println("Network added")
	case "del":
		if len(cfg.Command.IPs) < 1 {
			return ErrNoRequiredIPs
		}

		if err = fw.Remove(cfg.IsAccept, cfg.Command.IPs); err != nil {
			return err
		}

		fmt.Println("Network removed")
	case "list":
		var networks []string

		networks, err = fw.List(true)
		if err != nil {
			return err
		}

		fmt.Println("Allowed networks:")

		for _, network := range networks {
			fmt.Println(network)
		}

		networks, err = fw.List(false)
		if err != nil {
			return err
		}

		fmt.Println("Blocked networks:")

		for _, network := range networks {
			fmt.Println(network)
		}
	default:
		return ErrUnknownCommand
	}

	return err
}
