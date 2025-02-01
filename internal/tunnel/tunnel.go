package tunnel

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"

	"tunnel/internal/config"
	"tunnel/pkg/sshclient"
)

const (
	// 重试间隔时间
	retryInterval = 5 * time.Second
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

// Start 启动隧道并保持连接
func (t *Tunnel) Start(ctx context.Context) error {
	// 记录启动时间
	startTime := time.Now()
	log.Info().Str("tunnel", t.Name()).Msg("Starting tunnel")

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
			// 尝试连接
			err := t.connect(ctx)
			if err != nil {
				t.retryCount++
				log.Warn().Err(err).Str("tunnel", t.Name()).Int("retryCount", t.retryCount).Msg("Tunnel connection failed")

				// 检查是否需要退出
				select {
				case <-ctx.Done():
					return fmt.Errorf("tunnel stopped due to context cancel: %w", err)
				case <-time.After(retryInterval):
					// 等待重试间隔后继续
					continue
				}
			} else {
				// 连接成功,重置重试计数
				t.retryCount = 0
			}
		}
	}
}

// connect 建立隧道连接
func (t *Tunnel) connect(ctx context.Context) error {
	timeoutDuration := 10 * time.Second
	if t.server.Timeout > 0 {
		timeoutDuration = time.Duration(t.server.Timeout) * time.Second
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, timeoutDuration)
	defer cancel()

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

	if err := t.client.Connect(timeoutCtx); err != nil {
		return fmt.Errorf("failed to connect (timeout after %ds): %w", t.server.Timeout, err)
	}

	return t.setupTunnel(ctx)
}

// setupTunnel 设置端口转发
func (t *Tunnel) setupTunnel(ctx context.Context) error {
	var err error
	switch t.config.Type {
	case "local_to_remote":
		err = t.client.LocalToRemote(ctx, t.config.LocalHost, t.config.LocalPort,
			t.config.RemoteHost, t.config.RemotePort)
	case "remote_to_local":
		err = t.client.RemoteToLocal(ctx, t.config.LocalHost, t.config.LocalPort,
			t.config.RemoteHost, t.config.RemotePort)
	default:
		err = fmt.Errorf("unknown tunnel type: %s", t.config.Type)
	}

	if err != nil {
		t.client.Close()
		return fmt.Errorf("tunnel failed: %w", err)
	}

	return nil
}

// Name 获取隧道名称
func (t *Tunnel) Name() string {
	return fmt.Sprintf("%s-%s", t.server.Name, t.config.Name)
}
