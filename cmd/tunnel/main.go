package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"tunnel/internal/config"
	"tunnel/internal/tunnel"

	"github.com/spf13/pflag"
)

const (
	defaultConfigName = "config.yaml"
)

// 获取可能的配置文件路径
func getConfigPaths(configPath string) []string {
	// 如果通过命令行指定了配置文件，则只使用指定的路径
	if configPath != "" {
		return []string{configPath}
	}

	// 默认的配置文件搜索路径
	paths := []string{
		// 当前目录
		filepath.Join(".", defaultConfigName),
		// /etc/auto-tunnel/
		filepath.Join("/etc/auto-tunnel", defaultConfigName),
		// 用户主目录
		filepath.Join(os.Getenv("HOME"), ".auto-tunnel", defaultConfigName),
	}

	return paths
}

// 查找第一个存在的配置文件
func findConfigFile(paths []string) (string, error) {
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			log.Printf("Using config file: %s", path)
			return path, nil
		}
	}
	return "", fmt.Errorf("no config file found in: %v", paths)
}

func main() {
	// 使用 pflag 支持更多的命令行参数格式
	var configPath string
	pflag.StringVarP(&configPath, "config", "c", "", "Path to configuration file")
	pflag.Parse()

	// 获取所有可能的配置文件路径
	configPaths := getConfigPaths(configPath)

	// 查找可用的配置文件
	foundConfigPath, err := findConfigFile(configPaths)
	if err != nil {
		log.Fatalf("Failed to find config file: %v", err)
	}

	// 创建带取消的 context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 加载配置
	cfg, err := config.LoadConfig(foundConfigPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 创建隧道管理器
	manager := tunnel.NewManager(cfg)

	// 启动所有隧道
	if err := manager.Start(ctx); err != nil {
		log.Fatalf("Failed to start tunnel manager: %v", err)
	}

	// 等待信号以优雅退出
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	// 取消 context
	cancel()

	// 优雅关闭
	manager.Stop()
}
