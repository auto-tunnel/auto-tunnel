package sshclient

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

// 类型定义
// -----------------------------

// TunnelConfig 隧道配置结构
type TunnelConfig struct {
	LocalHost  string
	LocalPort  int
	RemoteHost string
	RemotePort int
	IsRemote   bool
}

// Client SSH 客户端结构
type Client struct {
	sshClientConfig *ssh.ClientConfig
	client          *ssh.Client
	host            string
	port            int
	timeout         int
	listeners       []net.Listener
	mu              sync.Mutex
	reconnectDelay  time.Duration
	maxRetries      int
	isConnected     atomic.Bool
	// 添加隧道配置存储
	tunnels []TunnelConfig
}

// SSHConfig SSH 配置文件解析结构
type SSHConfig struct {
	Host         string
	HostName     string
	Port         int
	User         string
	IdentityFile string
	ProxyCommand string
	ProxyJump    string
}

// SSH 配置相关
// -----------------------------

// loadSSHConfig 从 SSH 配置文件加载主机配置
func loadSSHConfig(host string) (*SSHConfig, error) {
	configPath, err := expandPath("~/.ssh/config")
	if err != nil {
		return nil, nil
	}

	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		log.Error().Err(err).Msg("failed to read ssh config file")
		return nil, err
	}

	return parseSSHConfig(configBytes, host)
}

// parseSSHConfig 解析 SSH 配置文件内容
func parseSSHConfig(configBytes []byte, targetHost string) (*SSHConfig, error) {
	config := &SSHConfig{Host: targetHost}
	var defaultConfig SSHConfig
	var currentConfig *SSHConfig
	var currentHost string

	lines := strings.Split(string(configBytes), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		key := strings.ToLower(parts[0])
		value := strings.Join(parts[1:], " ")

		if key == "host" {
			currentHost = value
			if currentHost == "*" {
				currentConfig = &defaultConfig
			} else if matchHost(targetHost, currentHost) {
				currentConfig = config
			} else {
				currentConfig = nil
			}
			continue
		}

		if currentConfig == nil {
			continue
		}

		switch key {
		case "hostname":
			currentConfig.HostName = value
		case "port":
			if port, err := strconv.Atoi(value); err == nil {
				currentConfig.Port = port
			}
		case "user":
			currentConfig.User = value
		case "identityfile":
			currentConfig.IdentityFile = value
		case "proxycommand":
			currentConfig.ProxyCommand = value
		case "proxyjump":
			currentConfig.ProxyJump = value
		}
	}

	// 应用默认配置（如果存在且目标配置中对应字段为空）
	if config.HostName == "" {
		config.HostName = defaultConfig.HostName
	}
	if config.Port == 0 {
		config.Port = defaultConfig.Port
	}
	if config.User == "" {
		config.User = defaultConfig.User
	}
	if config.IdentityFile == "" {
		config.IdentityFile = defaultConfig.IdentityFile
	}
	if config.ProxyCommand == "" {
		config.ProxyCommand = defaultConfig.ProxyCommand
	}
	if config.ProxyJump == "" {
		config.ProxyJump = defaultConfig.ProxyJump
	}

	// 如果没有找到主机名，但有默认配置，使用目标主机名作为主机名
	if config.HostName == "" && defaultConfig.User != "" {
		config.HostName = targetHost
	}

	return config, nil
}

// matchHost 检查目标主机是否匹配SSH配置中的Host模式
func matchHost(target, pattern string) bool {
	// 将模式转换为正则表达式
	pattern = strings.ReplaceAll(pattern, ".", "\\.")
	pattern = strings.ReplaceAll(pattern, "*", ".*")
	pattern = strings.ReplaceAll(pattern, "?", ".")
	pattern = "^" + pattern + "$"

	matched, err := regexp.MatchString(pattern, target)
	if err != nil {
		return false
	}
	return matched
}

// 客户端创建和连接
// -----------------------------

// NewClient 创建新的 SSH 客户端
func NewClient(host string, port int, user string, authMethod string, keyPath string, password string, timeout int) (*Client, error) {
	log.Info().Str("host", host).Int("port", port).Str("user", user).Str("authMethod", authMethod).Msg("Initial config")

	// 设置默认值
	if port == 0 {
		port = 22
	}

	// 尝试从SSH配置文件加载配置
	sshConfig, err := loadSSHConfig(host)
	if err != nil {
		log.Error().Err(err).Msg("failed to load ssh config")
	}

	// 处理用户名优先级：
	// 1. YAML配置中指定的用户名
	// 2. SSH配置中的用户名（包括默认配置）
	// 3. 系统环境变量
	if user == "" && sshConfig != nil && sshConfig.User != "" {
		user = sshConfig.User
		log.Info().Str("user", user).Msg("Using user from SSH config")
	}
	if user == "" {
		user = os.Getenv("USER")
		if user == "" {
			user = os.Getenv("USERNAME") // 为Windows系统
		}
		log.Info().Str("user", user).Msg("Using system user")
	}

	// 处理主机名和端口
	if sshConfig != nil {
		if sshConfig.HostName != "" && host == sshConfig.Host {
			log.Info().Str("host", host).Str("sshConfig.HostName", sshConfig.HostName).Msg("Using SSH config")
			host = sshConfig.HostName
		}
		if port == 22 && sshConfig.Port > 0 {
			port = sshConfig.Port
		}
	}

	// 确定认证方法和相关参数
	if authMethod == "" {
		// 根据提供的参数自动确定认证方法
		switch {
		case keyPath != "":
			authMethod = "key"
			log.Info().Str("keyPath", keyPath).Msg("Using key authentication with specified key path")
		case password != "":
			authMethod = "password"
			log.Info().Msg("Using password authentication")
		case sshConfig != nil && sshConfig.IdentityFile != "":
			authMethod = "key"
			keyPath = sshConfig.IdentityFile
			log.Info().Str("keyPath", keyPath).Msg("Using identity file from SSH config")
		default:
			return nil, fmt.Errorf("no authentication method available: please provide either key_path or password")
		}
	}

	// 根据认证方法验证和补充参数
	switch authMethod {
	case "key":
		if keyPath == "" {
			if sshConfig != nil && sshConfig.IdentityFile != "" {
				keyPath = sshConfig.IdentityFile
				log.Info().Str("keyPath", keyPath).Msg("Using identity file from SSH config")
			} else {
				return nil, fmt.Errorf("key_path is required for key authentication")
			}
		}
	case "password":
		if password == "" {
			return nil, fmt.Errorf("password is required for password authentication")
		}
	default:
		return nil, fmt.Errorf("unsupported auth method: %s", authMethod)
	}

	sshClientConfig, err := newSSHClientConfig(user, authMethod, keyPath, password, timeout)
	if err != nil {
		return nil, err
	}

	return &Client{
		sshClientConfig: sshClientConfig,
		host:            host,
		port:            port,
		timeout:         timeout,
		listeners:       make([]net.Listener, 0),
		reconnectDelay:  5 * time.Second, // 重连延迟5秒
		maxRetries:      -1,              // -1表示无限重试
	}, nil
}

// newSSHClientConfig 创建 SSH 客户端配置
func newSSHClientConfig(user, authMethod, keyPath, password string, timeout int) (*ssh.ClientConfig, error) {
	var auths []ssh.AuthMethod

	log.Info().Str("user", user).Str("authMethod", authMethod).Str("keyPath", keyPath).Msg("Creating SSH config")

	switch authMethod {
	case "key":
		if keyPath == "" {
			return nil, fmt.Errorf("key_path is required for key authentication")
		}
		expandedPath, err := expandPath(keyPath)
		if err != nil {
			log.Error().Err(err).Str("keyPath", keyPath).Msg("Failed to expand key path")
			return nil, fmt.Errorf("failed to expand key path: %w", err)
		}
		log.Info().Str("expandedPath", expandedPath).Msg("Using expanded key path")

		buffer, err := os.ReadFile(expandedPath)
		if err != nil {
			log.Error().Err(err).Str("expandedPath", expandedPath).Msg("Failed to read key file")
			return nil, fmt.Errorf("failed to read key file: %w", err)
		}

		key, err := ssh.ParsePrivateKey(buffer)
		if err != nil {
			log.Error().Err(err).Str("expandedPath", expandedPath).Msg("Failed to parse private key")
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		log.Info().Str("expandedPath", expandedPath).Msg("Successfully loaded private key")

		auths = append(auths, ssh.PublicKeys(key))
	case "password":
		if password == "" {
			return nil, fmt.Errorf("password is required for password authentication")
		}
		auths = append(auths, ssh.Password(password))
		log.Info().Msg("Using password authentication")
	default:
		return nil, fmt.Errorf("unsupported auth method: %s", authMethod)
	}

	timeoutDuration := 10 * time.Second
	if timeout > 0 {
		timeoutDuration = time.Duration(timeout) * time.Second
	}

	return &ssh.ClientConfig{
		User:            user,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeoutDuration,
		Config: ssh.Config{
			Ciphers: []string{
				"aes128-ctr", "aes192-ctr", "aes256-ctr",
				"aes128-gcm@openssh.com", "chacha20-poly1305@openssh.com",
				"arcfour256", "arcfour128", "aes128-cbc",
				"3des-cbc", "blowfish-cbc", "cast128-cbc",
				"aes192-cbc", "aes256-cbc",
			},
			MACs: []string{
				"hmac-sha2-256-etm@openssh.com", "hmac-sha2-256",
				"hmac-sha1", "hmac-sha1-96",
			},
		},
		BannerCallback: func(message string) error {
			log.Info().Str("message", message).Msg("SSH Banner")
			return nil
		},
	}, nil
}

// Connect 连接到 SSH 服务器
func (c *Client) Connect(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", c.host, c.port)

	// 启动保活和重连 goroutine
	go c.keepAliveAndReconnect(ctx)

	return c.connectWithRetry(ctx, addr)
}

// connectWithRetry 带重试的连接实现
func (c *Client) connectWithRetry(ctx context.Context, addr string) error {
	var lastErr error
	retries := 0

	for c.maxRetries < 0 || retries <= c.maxRetries {
		err := c.connectWithTimeout(ctx, addr)
		if err == nil {
			c.isConnected.Store(true)
			return nil
		}

		lastErr = err
		retries++

		log.Error().Err(err).Int("retries", retries).Str("reconnectDelay", c.reconnectDelay.String()).Msg("Connection attempt failed")

		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled during connection retry: %w", lastErr)
		case <-time.After(c.reconnectDelay):
			continue
		}
	}

	return fmt.Errorf("failed to connect after %d retries: %w", retries, lastErr)
}

// keepAliveAndReconnect 保持连接活跃并在断开时重连
func (c *Client) keepAliveAndReconnect(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if c.client == nil {
				continue
			}

			// 发送 keep-alive 消息
			_, _, err := c.client.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				log.Error().Err(err).Msg("Keep-alive failed")
				c.isConnected.Store(false)

				// 关闭旧连接
				c.client.Close()

				// 尝试重新连接
				addr := fmt.Sprintf("%s:%d", c.host, c.port)
				if err := c.connectWithRetry(ctx, addr); err != nil {
					log.Error().Err(err).Msg("Failed to reconnect")
					continue
				}

				// 重新建立所有端口转发
				c.reestablishTunnels(ctx)
			}
		}
	}
}

// reestablishTunnels 重新建立所有端口转发
func (c *Client) reestablishTunnels(ctx context.Context) {
	c.mu.Lock()
	tunnels := make([]TunnelConfig, len(c.tunnels))
	copy(tunnels, c.tunnels)
	c.mu.Unlock()

	// 关闭所有现有监听器
	c.mu.Lock()
	for _, l := range c.listeners {
		l.Close()
	}
	c.listeners = make([]net.Listener, 0)
	c.mu.Unlock()

	// 重新建立所有隧道
	for _, tunnel := range tunnels {
		select {
		case <-ctx.Done():
			log.Error().Msg("Context cancelled while reestablishing tunnels")
			return
		default:
			var err error
			if tunnel.IsRemote {
				err = c.RemoteToLocal(ctx, tunnel.LocalHost, tunnel.LocalPort, tunnel.RemoteHost, tunnel.RemotePort)
			} else {
				err = c.LocalToRemote(ctx, tunnel.LocalHost, tunnel.LocalPort, tunnel.RemoteHost, tunnel.RemotePort)
			}
			if err != nil {
				log.Error().Err(err).Str("tunnel", fmt.Sprintf("%s:%d -> %s:%d", tunnel.LocalHost, tunnel.LocalPort, tunnel.RemoteHost, tunnel.RemotePort)).Msg("Failed to reestablish tunnel")
			}
		}
	}
}

// connectWithTimeout 带超时的连接实现
func (c *Client) connectWithTimeout(ctx context.Context, addr string) error {
	var err error
	connectChan := make(chan bool, 1)
	errChan := make(chan error, 1)

	go func() {
		log.Info().Str("addr", addr).Msg("Attempting SSH connection")
		client, dialErr := ssh.Dial("tcp", addr, c.sshClientConfig)
		if dialErr != nil {
			log.Error().Err(dialErr).Msg("SSH connection failed")
			errChan <- fmt.Errorf("failed to create ssh client conn: %w", dialErr)
			return
		}
		c.client = client
		connectChan <- true
	}()

	select {
	case <-ctx.Done():
		return fmt.Errorf("connection timeout after %d seconds", c.timeout*2)
	case err = <-errChan:
		return err
	case <-connectChan:
		log.Info().Str("addr", addr).Msg("Successfully connected")
		return nil
	}
}

// Close 关闭客户端连接
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, l := range c.listeners {
		l.Close()
	}
	c.listeners = nil

	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

// 端口转发相关
// -----------------------------

// LocalToRemote 本地到远程的端口转发
// 在远程服务器上监听端口，将流量转发到本地指定的地址
func (c *Client) LocalToRemote(ctx context.Context, localHost string, localPort int, remoteHost string, remotePort int) error {
	// 保存隧道配置
	c.addTunnel(TunnelConfig{
		LocalHost:  localHost,
		LocalPort:  localPort,
		RemoteHost: remoteHost,
		RemotePort: remotePort,
		IsRemote:   false,
	})

	// 使用 RequestRemotePort 来请求端口转发
	addr := fmt.Sprintf("%s:%d", remoteHost, remotePort)
	log.Info().Str("addr", addr).Msg("Requesting remote port forward")

	// 请求远程端口转发
	ln, err := c.client.ListenTCP(&net.TCPAddr{
		IP:   net.ParseIP(remoteHost),
		Port: remotePort,
	})
	if err != nil {
		return fmt.Errorf("failed to request port forward: %w", err)
	}
	defer ln.Close()

	log.Info().Str("addr", addr).Str("localHost", localHost).Int("localPort", localPort).Msg("Successfully created listener on remote")

	var connCount int32
	var lastLogTime time.Time
	acceptChan := make(chan net.Conn)
	errChan := make(chan error)

	// 在单独的 goroutine 中进行 Accept
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if err == net.ErrClosed {
					return
				}
				errChan <- err
				return
			}
			acceptChan <- conn
		}
	}()

	// 主循环
	for {
		if time.Since(lastLogTime) > 30*time.Second {
			log.Info().Str("addr", addr).Msg("Waiting for connection on remote")
			lastLogTime = time.Now()
		}

		select {
		case <-ctx.Done():
			log.Info().Str("addr", addr).Msg("Context cancelled, closing remote listener")
			return nil
		case err := <-errChan:
			log.Error().Err(err).Str("addr", addr).Msg("Accept error")
			return err
		case remote := <-acceptChan:
			log.Info().Str("addr", addr).Str("remote", remote.RemoteAddr().String()).Msg("Accepted remote connection")

			connID := atomic.AddInt32(&connCount, 1)
			go func(remote net.Conn) {
				localAddr := fmt.Sprintf("%s:%d", localHost, localPort)
				remoteAddr := remote.RemoteAddr().String()
				log.Info().Int32("connID", connID).Str("remoteAddr", remoteAddr).Str("localAddr", localAddr).Msg("New connection")

				defer func() {
					remote.Close()
					log.Info().Int32("connID", connID).Msg("Connection closed")
				}()

				// 连接到本地目标地址
				local, err := net.Dial("tcp", localAddr)
				if err != nil {
					log.Error().Err(err).Int32("connID", connID).Str("localAddr", localAddr).Msg("Failed to connect to local")
					return
				}
				defer local.Close()

				// 双向转发数据
				done := make(chan struct{}, 2)
				go func() {
					n, err := io.Copy(local, remote)
					log.Info().Int32("connID", connID).Int64("n", n).Err(err).Msg("Copied from remote to local")
					done <- struct{}{}
				}()
				go func() {
					n, err := io.Copy(remote, local)
					log.Info().Int32("connID", connID).Int64("n", n).Err(err).Msg("Copied from local to remote")
					done <- struct{}{}
				}()

				<-done
			}(remote)
		}
	}
}

// RemoteToLocal 远程端口转发到本地
func (c *Client) RemoteToLocal(ctx context.Context, localHost string, localPort int, remoteHost string, remotePort int) error {
	// 保存隧道配置
	c.addTunnel(TunnelConfig{
		LocalHost:  localHost,
		LocalPort:  localPort,
		RemoteHost: remoteHost,
		RemotePort: remotePort,
		IsRemote:   true,
	})

	return c.createTunnel(ctx, localHost, localPort, remoteHost, remotePort, true)
}

// createTunnel 创建隧道连接
func (c *Client) createTunnel(ctx context.Context, localHost string, localPort int, remoteHost string, remotePort int, isRemote bool) error {
	if localHost == "" {
		localHost = "127.0.0.1"
	}

	tunnelType := "local_to_remote"
	if isRemote {
		tunnelType = "remote_to_local"
	}
	log.Info().Str("tunnelType", tunnelType).Str("localHost", localHost).Int("localPort", localPort).Str("remoteHost", remoteHost).Int("remotePort", remotePort).Msg("Creating tunnel")

	var lastErr error
	for {
		listener, err := c.createListener(localHost, localPort)
		if err != nil {
			return fmt.Errorf("failed to create %s tunnel listener: %w", tunnelType, err)
		}

		if err := c.handleConnections(ctx, listener, remoteHost, remotePort); err != nil {
			lastErr = err
			log.Error().Err(err).Str("tunnelType", tunnelType).Msg("Tunnel error")
			listener.Close()

			select {
			case <-ctx.Done():
				return fmt.Errorf("context cancelled for %s tunnel: %w", tunnelType, lastErr)
			case <-time.After(c.reconnectDelay):
				continue
			}
		}

		return nil
	}
}

func (c *Client) createListener(host string, port int) (net.Listener, error) {
	log.Info().Str("host", host).Int("port", port).Msg("Creating listener")

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s:%d: %w", host, port, err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.listeners = append(c.listeners, listener)

	return listener, nil
}

func (c *Client) handleConnections(ctx context.Context, listener net.Listener, remoteHost string, remotePort int) error {
	go func() {
		<-ctx.Done()
		log.Info().Int("port", c.port).Msg("Closing listener")
		listener.Close()
	}()

	var connCount int32

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			local, err := listener.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				if err == net.ErrClosed {
					return nil
				}
				log.Error().Err(err).Msg("failed to accept local connection")
				return err
			}

			connID := atomic.AddInt32(&connCount, 1)

			go func(local net.Conn) {
				remoteAddr := fmt.Sprintf("%s:%d", remoteHost, remotePort)
				localAddr := local.RemoteAddr().String()
				log.Info().Int32("connID", connID).Str("localAddr", localAddr).Str("remoteAddr", remoteAddr).Msg("New connection")

				defer func() {
					local.Close()
					log.Info().Int32("connID", connID).Str("localAddr", localAddr).Str("remoteAddr", remoteAddr).Msg("Connection closed")
				}()

				remote, err := c.client.Dial("tcp", remoteAddr)
				if err != nil {
					log.Error().Err(err).Int32("connID", connID).Str("remoteAddr", remoteAddr).Msg("Failed to dial remote")
					return
				}
				defer remote.Close()

				c.proxyConn(ctx, local, remote, connID)
			}(local)
		}
	}
}

func (c *Client) proxyConn(ctx context.Context, conn1, conn2 net.Conn, connID int32) {
	done := make(chan struct{}, 2)
	var bytesIn, bytesOut int64

	copyData := func(dst, src net.Conn, byteCount *int64) {
		defer func() { done <- struct{}{} }()
		*byteCount = copyDataWithCount(dst, src)
	}

	go copyData(conn1, conn2, &bytesIn)
	go copyData(conn2, conn1, &bytesOut)

	// 设置超时检测
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// 检查连接是否仍然活跃
				if !c.isConnected.Load() {
					conn1.Close()
					conn2.Close()
					return
				}
			}
		}
	}()

	select {
	case <-ctx.Done():
		conn1.Close()
		conn2.Close()
	case <-done:
		log.Printf("[Conn-%d] Connection finished. Bytes in: %d, Bytes out: %d",
			connID, bytesIn, bytesOut)
	}
}

func copyDataWithCount(dst, src net.Conn) int64 {
	defer dst.Close()
	defer src.Close()

	buffer := make([]byte, 32*1024)
	var total int64

	for {
		nr, err := src.Read(buffer)
		if err != nil {
			return total
		}
		if nr > 0 {
			nw, err := dst.Write(buffer[0:nr])
			if err != nil {
				return total
			}
			if nw != nr {
				return total
			}
			total += int64(nr)
		}
	}
}

func expandPath(path string) (string, error) {
	if len(path) == 0 {
		return path, nil
	}

	if path[0] != '~' {
		return path, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %v", err)
	}

	if len(path) == 1 {
		return home, nil
	}

	if path[1] != '/' {
		return "", fmt.Errorf("invalid path format")
	}

	return filepath.Join(home, path[2:]), nil
}

func publicKeyFile(file string) (ssh.AuthMethod, error) {
	expandedPath, err := expandPath(file)
	if err != nil {
		log.Printf("failed to expand path %s: %v", file, err)
		return nil, err
	}

	buffer, err := os.ReadFile(expandedPath)
	if err != nil {
		log.Printf("failed to read key file %s: %v", expandedPath, err)
		return nil, err
	}

	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		log.Printf("failed to parse private key %s: %v", expandedPath, err)
		return nil, err
	}

	return ssh.PublicKeys(key), nil
}

// addTunnel 添加隧道配置
func (c *Client) addTunnel(config TunnelConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tunnels = append(c.tunnels, config)
}
