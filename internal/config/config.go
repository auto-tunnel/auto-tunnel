package config

import (
	"fmt"
	"net"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Servers []ServerConfig `mapstructure:"servers"`
}

type ServerConfig struct {
	Name       string         `mapstructure:"name"`
	Host       string         `mapstructure:"host"`
	Port       int            `mapstructure:"port"`
	User       string         `mapstructure:"user"`
	AuthMethod string         `mapstructure:"auth_method"`
	KeyPath    string         `mapstructure:"key_path"`
	Password   string         `mapstructure:"password"`
	Timeout    int            `mapstructure:"timeout"`
	Tunnels    []TunnelConfig `mapstructure:"tunnels"`
}

type TunnelConfig struct {
	Name       string `mapstructure:"name"`
	Type       string `mapstructure:"type"`
	LocalHost  string `mapstructure:"local_host" default:"127.0.0.1"`
	LocalPort  int    `mapstructure:"local_port"`
	RemotePort int    `mapstructure:"remote_port"`
	RemoteHost string `mapstructure:"remote_host"`
}

func LoadConfig(path string) (*Config, error) {
	v := viper.New()

	// 设置配置文件信息
	v.SetConfigFile(path)
	v.SetConfigType("yaml")

	// 设置默认值
	setDefaults(v)

	// 读取配置文件
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// 设置默认值
	for i := range config.Servers {
		for j := range config.Servers[i].Tunnels {
			if config.Servers[i].Tunnels[j].LocalHost == "" {
				config.Servers[i].Tunnels[j].LocalHost = "127.0.0.1"
			}
		}
	}

	// 验证配置
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &config, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("servers", []ServerConfig{})
}

func validateConfig(cfg *Config) error {
	if len(cfg.Servers) == 0 {
		return fmt.Errorf("no servers configured")
	}

	for i, server := range cfg.Servers {
		if err := validateServer(server, i); err != nil {
			return err
		}
	}

	return nil
}

func validateServer(server ServerConfig, index int) error {
	if server.Name == "" {
		return fmt.Errorf("server[%d]: name is required", index)
	}
	if server.Host == "" {
		return fmt.Errorf("server[%d]: host is required", index)
	}
	if server.Port <= 0 || server.Port > 65535 {
		return fmt.Errorf("server[%d]: invalid port number", index)
	}
	if server.User == "" {
		return fmt.Errorf("server[%d]: user is required", index)
	}

	// 验证认证方法
	server.AuthMethod = strings.ToLower(server.AuthMethod)
	if server.AuthMethod != "password" && server.AuthMethod != "key" {
		return fmt.Errorf("server[%d]: auth_method must be either 'password' or 'key'", index)
	}

	if server.AuthMethod == "key" && server.KeyPath == "" {
		return fmt.Errorf("server[%d]: key_path is required when using key authentication", index)
	}
	if server.AuthMethod == "password" && server.Password == "" {
		return fmt.Errorf("server[%d]: password is required when using password authentication", index)
	}

	// 验证隧道配置
	for j, tunnel := range server.Tunnels {
		if err := validateTunnel(tunnel, index, j); err != nil {
			return err
		}
	}

	return nil
}

func validateTunnel(tunnel TunnelConfig, serverIndex, tunnelIndex int) error {
	if tunnel.Name == "" {
		return fmt.Errorf("server[%d].tunnels[%d]: name is required", serverIndex, tunnelIndex)
	}

	tunnel.Type = strings.ToLower(tunnel.Type)
	if tunnel.Type != "remote_to_local" && tunnel.Type != "local_to_remote" {
		return fmt.Errorf("server[%d].tunnels[%d]: type must be either 'remote_to_local' or 'local_to_remote'",
			serverIndex, tunnelIndex)
	}

	if tunnel.LocalPort <= 0 || tunnel.LocalPort > 65535 {
		return fmt.Errorf("server[%d].tunnels[%d]: invalid local_port", serverIndex, tunnelIndex)
	}
	if tunnel.RemotePort <= 0 || tunnel.RemotePort > 65535 {
		return fmt.Errorf("server[%d].tunnels[%d]: invalid remote_port", serverIndex, tunnelIndex)
	}
	if tunnel.RemoteHost == "" {
		return fmt.Errorf("server[%d].tunnels[%d]: remote_host is required", serverIndex, tunnelIndex)
	}
	// 如果指定了 LocalHost，验证是否是有效的 IP 地址或主机名
	if tunnel.LocalHost != "" && tunnel.LocalHost != "localhost" {
		if net.ParseIP(tunnel.LocalHost) == nil {
			// 不是有效的 IP 地址，尝试解析主机名
			if _, err := net.LookupHost(tunnel.LocalHost); err != nil {
				return fmt.Errorf("server[%d].tunnels[%d]: invalid local_host", serverIndex, tunnelIndex)
			}
		}
	}

	return nil
}
