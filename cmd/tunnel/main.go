package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"syscall"
	"time"

	"tunnel/internal/config"
	"tunnel/internal/tunnel"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/pflag"
)

const (
	defaultConfigName = "config.yaml"
)

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
	InitLog()

	// 使用 pflag 支持更多的命令行参数格式
	var configPath string
	pflag.StringVarP(&configPath, "config", "c", "", "Path to configuration file")
	pflag.Parse()

	// 获取所有可能的配置文件路径
	var configPaths []string
	configPaths = append(configPaths, configPath)
	configPaths = append(configPaths, filepath.Join(".", defaultConfigName))
	configPaths = append(configPaths, filepath.Join("/etc/auto-tunnel", defaultConfigName))
	configPaths = append(configPaths, filepath.Join(os.Getenv("HOME"), ".auto-tunnel", defaultConfigName))

	// 查找可用的配置文件
	var foundConfigPath string
	for _, path := range configPaths {
		if _, err := os.Stat(path); err == nil {
			log.Printf("Using config file: %s", path)
			foundConfigPath = path
			break
		}
	}

	log.Printf("foundConfigPath: %v", foundConfigPath)

	// 创建带取消的 context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 加载配置
	cfg, err := config.LoadConfig(foundConfigPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}

	// 创建隧道管理器
	manager := tunnel.NewManager(cfg)

	// 启动所有隧道
	if err := manager.Start(ctx); err != nil {
		log.Fatal().Err(err).Msg("Failed to start tunnel manager")
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

func InitLog() {
	outer := zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
		FormatCaller: func(i interface{}) string {
			_, f := path.Split(i.(string))
			return "[" + fmt.Sprintf("%-20s", f) + "]"
		},
	}
	log.Logger = zerolog.New(zerolog.MultiLevelWriter(outer)).With().Caller().Timestamp().Stack().Logger()
}
