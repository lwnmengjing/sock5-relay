package config

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/mss-boot-io/mss-boot/pkg/config"
	"github.com/mss-boot-io/mss-boot/pkg/config/source"
)

var Cfg = &Config{}

type Config struct {
	Logger  config.Logger        `yaml:"logger" json:"logger"`
	Regions map[string]RegionSet `yaml:"regions" json:"regions"`
}

type RegionSet struct {
	Region   string    `yaml:"region" json:"region"`
	Machines []Machine `yaml:"machines" json:"machines"`
}

type Machine struct {
	IP        string `yaml:"ip" json:"ip"`
	StartPort uint   `yaml:"startPort" json:"startPort"`
	EndPort   uint   `yaml:"endPort" json:"endPort"`
}

func (e *Config) Init() {
	opts := []source.Option{
		source.WithDir("config"),
		source.WithProvider(source.Local),
		source.WithWatch(true),
	}
	err := config.Init(e, opts...)
	if err != nil {
		slog.Error("cfg init failed", "err", err)
		os.Exit(-1)
	}
	e.Logger.Init()
}

func (e *Config) GetIP(region string, index int) string {
	ips, ok := e.Regions[region]
	if !ok || len(ips.Machines) == 0 {
		return ""
	}
	if index >= len(ips.Machines) {
		return ips.Machines[len(ips.Machines)-1].IP
	}
	return ips.Machines[index].IP
}

func (e *Config) OnChange() {
	fmt.Println("config changed")
	e.Logger.Init()
}
