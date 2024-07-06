package config

import (
	"errors"
	"os"

	"gopkg.in/yaml.v2"
)

type RestrictedNetworkConfig struct {
	Enable  bool
	Mode    string        `yaml:"mode"`
	Target  string        `yaml:"target"`
	Command CommandConfig `yaml:"command"`
	CIDR    CIDRConfig    `yaml:"cidr"`
	Domain  DomainConfig  `yaml:"domain"`
	UID     UIDConfig     `yaml:"uid"`
	GID     GIDConfig     `yaml:"gid"`
}

type RestrictedFileAccessConfig struct {
	Enable bool
	Mode   string   `yaml:"mode"`
	Target string   `yaml:"target"`
	Allow  []string `yaml:"allow"`
	Deny   []string `yaml:"deny"`
}

type SignalLogConfig struct {
	Enable bool
	Mode   string     `yaml:"mode"`
	Type   SignalType `yaml:"type"`
	// Target string `yaml:"target"`
	// PID PIDConfig `yaml:"pid"`
	// Command CommandConfig `yaml:"command"`
	// UID     UIDConfig     `yaml:"uid"`
	// GID     GIDConfig     `yaml:"gid"`
}

type RestrictedMountConfig struct {
	Enable         bool
	Mode           string   `yaml:"mode"`
	Target         string   `yaml:"target"`
	DenySourcePath []string `yaml:"deny"`
}

type DomainConfig struct {
	Allow    []string `yaml:"allow"`
	Deny     []string `yaml:"deny"`
	Interval uint     `yaml:"interval"` // deprecated
}

type DNSProxyConfig struct {
	Enable        bool     `yaml:"enable"`
	Upstreams     []string `yaml:"upstreams"`
	BindAddresses []string `yaml:"bind"`
}

type CIDRConfig struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

type CommandConfig struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

type SignalType struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}
type PIDConfig struct {
	Allow []uint `yaml:"allow"`
	Deny  []uint `yaml:"deny"`
}

type UIDConfig struct {
	Allow []uint `yaml:"allow"`
	Deny  []uint `yaml:"deny"`
}

type GIDConfig struct {
	Allow []uint `yaml:"allow"`
	Deny  []uint `yaml:"deny"`
}

type LogConfig struct {
	Level   string            `yaml:"level"`
	Format  string            `yaml:"format"`
	Output  string            `yaml:"output"`
	MaxSize int               `yaml:"max_size"`
	MaxAge  int               `yaml:"max_age"`
	Labels  map[string]string `yaml:"labels"`
}

type Config struct {
	RestrictedNetworkConfig    `yaml:"network"`
	RestrictedFileAccessConfig `yaml:"files"`
	RestrictedMountConfig      `yaml:"mount"`
	DNSProxyConfig             `yaml:"dns_proxy"`
	SignalLogConfig            `yaml:"signals"`
	Log                        LogConfig
}

func DefaultConfig() *Config {
	return &Config{
		RestrictedNetworkConfig: RestrictedNetworkConfig{
			Enable:  true,
			Mode:    "monitor",
			Target:  "host",
			Command: CommandConfig{Allow: []string{}, Deny: []string{}},
			CIDR:    CIDRConfig{Allow: []string{"0.0.0.0/0", "::/0"}, Deny: []string{}},
			Domain:  DomainConfig{Allow: []string{}, Deny: []string{}, Interval: 5},
			UID:     UIDConfig{Allow: []uint{}, Deny: []uint{}},
			GID:     GIDConfig{Allow: []uint{}, Deny: []uint{}},
		},
		RestrictedFileAccessConfig: RestrictedFileAccessConfig{
			Enable: true,
			Mode:   "monitor",
			Target: "host",
			Allow:  []string{"/"},
			Deny:   []string{},
		},
		RestrictedMountConfig: RestrictedMountConfig{
			Enable:         true,
			Mode:           "monitor",
			Target:         "host",
			DenySourcePath: []string{},
		},
		DNSProxyConfig: DNSProxyConfig{
			Enable:        false,
			Upstreams:     []string{},
			BindAddresses: []string{"127.0.0.1", "172.17.0.1"},
		},
		SignalLogConfig: SignalLogConfig{
			Enable: true,
			Mode:   "monitor",
			Type: SignalType{
				Allow: []string{"/"},
				Deny:  []string{},
			},
		},

		Log: LogConfig{
			Level:  "INFO",
			Format: "json",
			Output: "stdout",
			Labels: map[string]string{},
		},
	}
}

func NewConfig(configPath string) (*Config, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	d := yaml.NewDecoder(file)

	config := DefaultConfig()
	if err := d.Decode(&config); err != nil {
		return nil, err
	}

	err = config.Validate()
	if err != nil {
		return nil, err
	}

	return config, nil
}

func (c *Config) Validate() error {
	if c.DNSProxyConfig.Enable && len(c.DNSProxyConfig.Upstreams) == 0 {
		return errors.New("One or more dns_proxy.upstrems must be specified.")
	}

	return nil
}

func (c *Config) EnableDNSProxy() bool {
	return c.DNSProxyConfig.Enable
}

func (c *Config) IsRestrictedMode(target string) bool {
	switch target {
	case "network":
		if c.RestrictedNetworkConfig.Mode == "block" {
			return true
		} else {
			return false
		}
	case "fileaccess":
		if c.RestrictedFileAccessConfig.Mode == "block" {
			return true
		} else {
			return false
		}
	case "mount":
		if c.RestrictedMountConfig.Mode == "block" {
			return true
		} else {
			return false
		}
	default:
		return false
	}
}

func (c *Config) IsOnlyContainer(target string) bool {
	switch target {
	case "network":
		if c.RestrictedNetworkConfig.Target == "container" {
			return true
		} else {
			return false
		}
	case "fileaccess":
		if c.RestrictedFileAccessConfig.Target == "container" {
			return true
		} else {
			return false
		}
	case "mount":
		if c.RestrictedMountConfig.Target == "container" {
			return true
		} else {
			return false
		}
	default:
		return false
	}
}
