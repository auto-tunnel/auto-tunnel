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
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewTunnel 创建新的隧道实例
func NewTunnel(server config.ServerConfig, config config.TunnelConfig) *Tunnel {
	ctx, cancel := context.WithCancel(context.Background())
	return &Tunnel{
		server: server,
		config: config,
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start 启动隧道并保持连接
func (t *Tunnel) Start(ctx context.Context) error {
	ctx = t.ctx

	for {
		select {
		case <-ctx.Done():
			return t.handleShutdown()
		default:
			if err := t.connect(ctx); err != nil {
				if !t.handleError(ctx, err) {
					return err
				}
			}
		}
	}
}

// connect 建立隧道连接
func (t *Tunnel) connect(ctx context.Context) error {
	timeoutDuration := t.getTimeoutDuration()
	timeoutCtx, cancel := context.WithTimeout(ctx, timeoutDuration)
	defer cancel()

	client, err := t.createSSHClient()
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

// handleError 处理错误并决定是否重试
func (t *Tunnel) handleError(ctx context.Context, err error) bool {
	log.Warn().Err(err).Str("tunnel", t.Name()).Msg("Tunnel connection failed")

	select {
	case <-ctx.Done():
		return false
	case <-time.After(retryInterval):
		return true
	}
}

// handleShutdown 处理隧道关闭
func (t *Tunnel) handleShutdown() error {
	log.Info().Str("tunnel", t.Name()).Msg("Tunnel stopping due to context cancellation")

	if t.client != nil {
		t.client.Close()
	}
	return nil
}

// createSSHClient 创建 SSH 客户端
func (t *Tunnel) createSSHClient() (*sshclient.Client, error) {
	return sshclient.NewClient(
		t.server.Host,
		t.server.Port,
		t.server.User,
		t.server.AuthMethod,
		t.server.KeyPath,
		t.server.Password,
		t.server.Timeout,
	)
}

// getTimeoutDuration 获取超时时间
func (t *Tunnel) getTimeoutDuration() time.Duration {
	timeoutDuration := 10 * time.Second
	if t.server.Timeout > 0 {
		timeoutDuration = time.Duration(t.server.Timeout) * time.Second
	}
	return timeoutDuration
}

// Name 获取隧道名称
func (t *Tunnel) Name() string {
	return fmt.Sprintf("%s-%s", t.server.Name, t.config.Name)
}

// Close 关闭隧道
func (t *Tunnel) Close() {
	t.cancel()
	if t.client != nil {
		t.client.Close()
	}
}
