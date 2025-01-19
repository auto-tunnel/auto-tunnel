package tunnel

import (
	"context"
	"log"
	"sync"
	"time"

	"tunnel/internal/config"
)

// Manager 管理多个隧道的生命周期
type Manager struct {
	config  *config.Config
	tunnels []*Tunnel
	wg      sync.WaitGroup
}

// NewManager 创建新的隧道管理器
func NewManager(cfg *config.Config) *Manager {
	return &Manager{
		config:  cfg,
		tunnels: make([]*Tunnel, 0),
	}
}

// Start 启动所有隧道
func (m *Manager) Start(ctx context.Context) error {
	// 为每个服务器配置创建隧道
	for _, server := range m.config.Servers {
		for _, tunnelCfg := range server.Tunnels {
			tunnel := NewTunnel(server, tunnelCfg)
			m.tunnels = append(m.tunnels, tunnel)

			m.wg.Add(1)
			go m.runTunnel(ctx, tunnel)
		}
	}
	return nil
}

// runTunnel 在独立的 goroutine 中运行隧道
func (m *Manager) runTunnel(ctx context.Context, t *Tunnel) {
	defer m.wg.Done()
	if err := t.Start(ctx); err != nil {
		log.Printf("Failed to start tunnel %s: %v", t.Name(), err)
	}
}

// Stop 停止所有隧道
func (m *Manager) Stop() {
	log.Println("Waiting for all tunnels to close...")

	// 创建等待组，用于等待所有隧道关闭
	var wg sync.WaitGroup
	for _, tunnel := range m.tunnels {
		wg.Add(1)
		go func(t *Tunnel) {
			defer wg.Done()
			t.Close()
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
		log.Println("All tunnels closed")
	case <-time.After(5 * time.Second):
		log.Println("Force closing tunnels after timeout")
	}
}
