package tunnel

import (
	"context"
	"sync"
	"time"

	"tunnel/internal/config"

	"github.com/rs/zerolog/log"
)

// Manager 管理多个隧道的生命周期
type Manager struct {
	config  *config.Config
	tunnels []*Tunnel
}

// NewManager 创建新的隧道管理器
func NewManager(cfg *config.Config) *Manager {
	return &Manager{config: cfg, tunnels: make([]*Tunnel, 0)}
}

// Start 启动所有隧道
func (m *Manager) Start(ctx context.Context) error {
	// 为每个服务器配置创建隧道
	wg := sync.WaitGroup{}

	for _, server := range m.config.Servers {
		for _, tunnelCfg := range server.Tunnels {
			wg.Add(1)
			go func(tunnelCfg config.TunnelConfig) {
				defer wg.Done()

				tunnel := NewTunnel(server, tunnelCfg)
				m.tunnels = append(m.tunnels, tunnel)

				log.Info().Str("server", server.Name).Str("host", server.Host).Str("tunnel", tunnel.Name()).Msg("Starting tunnel")
				if err := tunnel.Start(ctx); err != nil {
					log.Error().Err(err).Str("tunnel", tunnel.Name()).Msg("Failed to start tunnel")
					return
				}
			}(tunnelCfg)
		}
	}

	wg.Wait()

	return nil
}

// Stop 停止所有隧道
func (m *Manager) Stop() {
	log.Info().Msg("Waiting for all tunnels to close...")

	// 创建等待组，用于等待所有隧道关闭
	var wg sync.WaitGroup
	for _, tunnel := range m.tunnels {
		wg.Add(1)
		go func(t *Tunnel) {
			defer wg.Done()
			if t.client != nil {
				t.client.Close()
			}
		}(tunnel)
	}

	// 设置超时时间，避免无限等待
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Info().Msg("All tunnels closed")
	case <-time.After(5 * time.Second):
		log.Error().Msg("Force closing tunnels after timeout")
	}
}
