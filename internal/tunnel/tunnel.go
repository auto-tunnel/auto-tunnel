package tunnel

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"

	"tunnel/internal/config"
	"tunnel/pkg/sshclient"
)

// Tunnel 表示单个 SSH 隧道
type Tunnel struct {
	server     config.ServerConfig
	config     config.TunnelConfig
	client     *sshclient.Client
	retryCount int
}

// NewTunnel 创建新的隧道实例
func NewTunnel(server config.ServerConfig, config config.TunnelConfig) *Tunnel {
	return &Tunnel{server: server, config: config}
}

// Name 获取隧道名称
func (t *Tunnel) Name() string {
	return fmt.Sprintf("%s-%s", t.server.Name, t.config.Name)
}

// Start 启动隧道并保持连接
func (t *Tunnel) Start(ctx context.Context) error {
	// 记录启动时间
	startTime := time.Now()

	for {
		select {
		case <-ctx.Done():
			// 收到取消信号,优雅关闭
			log.Info().Str("tunnel", t.Name()).Str("uptime", time.Since(startTime).String()).Msg("Tunnel stopping due to context cancellation")
			if t.client != nil {
				t.client.Close()
			}
			return nil

		default:
			if err := t.connect(ctx); err != nil {
				t.retryCount++
				log.Warn().Err(err).Str("tunnel", t.Name()).Int("retryCount", t.retryCount).Msg("Tunnel connection failed")
			}
		}
	}
}

// connect 建立隧道连接
func (t *Tunnel) connect(ctx context.Context) error {
	client, err := sshclient.NewClient(
		t.server.Host,
		t.server.Port,
		t.server.User,
		t.server.AuthMethod,
		t.server.KeyPath,
		t.server.Password,
		t.server.Timeout,
	)
	if err != nil {
		return fmt.Errorf("failed to create SSH client: %w", err)
	}

	t.client = client
	if err := t.client.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect (timeout after %ds): %w", t.server.Timeout, err)
	}

	switch t.config.Type {
	case "local_to_remote":
		err = t.client.LocalToRemote(ctx, t.config.LocalHost, t.config.LocalPort, t.config.RemoteHost, t.config.RemotePort)
	case "remote_to_local":
		err = t.client.RemoteToLocal(ctx, t.config.LocalHost, t.config.LocalPort, t.config.RemoteHost, t.config.RemotePort)
	default:
		err = fmt.Errorf("unknown tunnel type: %s", t.config.Type)
	}

	if err != nil {
		t.client.Close()
		return fmt.Errorf("tunnel failed: %w", err)
	}

	return nil
}
