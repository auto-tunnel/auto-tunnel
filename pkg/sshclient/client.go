package sshclient

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// 类型定义
// -----------------------------

// Client SSH 客户端结构
type Client struct {
	config    *ssh.ClientConfig
	client    *ssh.Client
	host      string
	port      int
	timeout   int
	listeners []net.Listener
	mu        sync.Mutex
}

// SSHConfig SSH 配置文件解析结构
type SSHConfig struct {
	Host         string
	HostName     string
	Port         int
	User         string
	IdentityFile string
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
		log.Printf("failed to read ssh config file: %v", err)
		return nil, err
	}

	return parseSSHConfig(configBytes, host)
}

// parseSSHConfig 解析 SSH 配置文件内容
func parseSSHConfig(configBytes []byte, targetHost string) (*SSHConfig, error) {
	config := &SSHConfig{Host: targetHost}
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
			continue
		}

		if currentHost != targetHost {
			continue
		}

		switch key {
		case "hostname":
			config.HostName = value
		case "port":
			if port, err := strconv.Atoi(value); err == nil {
				config.Port = port
			}
		case "user":
			config.User = value
		case "identityfile":
			config.IdentityFile = value
		}
	}

	if config.HostName == "" {
		return nil, nil
	}

	return config, nil
}

// 客户端创建和连接
// -----------------------------

// NewClient 创建新的 SSH 客户端
func NewClient(host string, port int, user string, authMethod string, keyPath string, password string, timeout int) (*Client, error) {
	sshConfig, err := loadSSHConfig(host)
	if err != nil {
		log.Printf("failed to load ssh config: %v", err)
	}

	// 应用 SSH 配置
	if sshConfig != nil {
		if sshConfig.HostName != "" {
			log.Printf("Using SSH config: %s -> %s", host, sshConfig.HostName)
			host = sshConfig.HostName
		}
		if sshConfig.Port > 0 {
			port = sshConfig.Port
		}
		if sshConfig.User != "" {
			user = sshConfig.User
		}
		if authMethod == "key" && sshConfig.IdentityFile != "" && keyPath == "" {
			keyPath = sshConfig.IdentityFile
		}
	}

	config, err := createSSHConfig(user, authMethod, keyPath, password, timeout)
	if err != nil {
		return nil, err
	}

	return &Client{
		config:    config,
		host:      host,
		port:      port,
		timeout:   timeout,
		listeners: make([]net.Listener, 0),
	}, nil
}

// createSSHConfig 创建 SSH 客户端配置
func createSSHConfig(user, authMethod, keyPath, password string, timeout int) (*ssh.ClientConfig, error) {
	var auths []ssh.AuthMethod

	switch authMethod {
	case "key":
		auth, err := publicKeyFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load key file: %w", err)
		}
		auths = append(auths, auth)
	case "password":
		auths = append(auths, ssh.Password(password))
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
			log.Printf("SSH Banner: %s", message)
			return nil
		},
	}, nil
}

// Connect 连接到 SSH 服务器
func (c *Client) Connect(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", c.host, c.port)
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(c.timeout*2)*time.Second)
	defer cancel()

	return c.connectWithTimeout(timeoutCtx, addr)
}

// connectWithTimeout 带超时的连接实现
func (c *Client) connectWithTimeout(ctx context.Context, addr string) error {
	var err error
	connectChan := make(chan bool, 1)
	errChan := make(chan error, 1)

	go func() {
		log.Printf("Attempting SSH connection to %s...", addr)
		client, dialErr := ssh.Dial("tcp", addr, c.config)
		if dialErr != nil {
			log.Printf("SSH connection failed: %v", dialErr)
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
		log.Printf("Successfully connected to %s", addr)
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
	// 使用 RequestRemotePort 来请求端口转发
	addr := fmt.Sprintf("%s:%d", remoteHost, remotePort)
	log.Printf("Requesting remote port forward for %s", addr)

	// 请求远程端口转发
	ln, err := c.client.ListenTCP(&net.TCPAddr{
		IP:   net.ParseIP(remoteHost),
		Port: remotePort,
	})
	if err != nil {
		return fmt.Errorf("failed to request port forward: %w", err)
	}
	defer ln.Close()

	log.Printf("Successfully created listener on remote %s, forwarding to %s:%d",
		addr, localHost, localPort)

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
			log.Printf("Waiting for connection on remote %s...", addr)
			lastLogTime = time.Now()
		}

		select {
		case <-ctx.Done():
			log.Printf("Context cancelled, closing remote listener on %s", addr)
			return nil
		case err := <-errChan:
			log.Printf("Accept error: %v", err)
			return err
		case remote := <-acceptChan:
			log.Printf("Accepted remote connection from %s", remote.RemoteAddr().String())

			connID := atomic.AddInt32(&connCount, 1)
			go func(remote net.Conn) {
				localAddr := fmt.Sprintf("%s:%d", localHost, localPort)
				remoteAddr := remote.RemoteAddr().String()
				log.Printf("[Conn-%d] New connection from %s, forwarding to %s",
					connID, remoteAddr, localAddr)

				defer func() {
					remote.Close()
					log.Printf("[Conn-%d] Connection closed", connID)
				}()

				// 连接到本地目标地址
				local, err := net.Dial("tcp", localAddr)
				if err != nil {
					log.Printf("[Conn-%d] Failed to connect to %s: %v",
						connID, localAddr, err)
					return
				}
				defer local.Close()

				// 双向转发数据
				done := make(chan struct{}, 2)
				go func() {
					n, err := io.Copy(local, remote)
					log.Printf("[Conn-%d] Copied %d bytes from remote to local, err: %v", connID, n, err)
					done <- struct{}{}
				}()
				go func() {
					n, err := io.Copy(remote, local)
					log.Printf("[Conn-%d] Copied %d bytes from local to remote, err: %v", connID, n, err)
					done <- struct{}{}
				}()

				<-done
			}(remote)
		}
	}
}

// RemoteToLocal 远程端口转发到本地
func (c *Client) RemoteToLocal(ctx context.Context, localHost string, localPort int, remoteHost string, remotePort int) error {
	return c.createTunnel(ctx, localHost, localPort, remoteHost, remotePort, true)
}

// createTunnel 创建隧道连接
func (c *Client) createTunnel(ctx context.Context, localHost string, localPort int, remoteHost string, remotePort int, isRemote bool) error {
	if localHost == "" {
		localHost = "127.0.0.1"
	}

	listener, err := c.createListener(localHost, localPort)
	if err != nil {
		return err
	}
	defer listener.Close()

	tunnelType := "local to remote"
	if isRemote {
		tunnelType = "remote to local"
	}
	log.Printf("Created %s tunnel: %s:%d -> %s:%d", tunnelType, localHost, localPort, remoteHost, remotePort)

	return c.handleConnections(ctx, listener, remoteHost, remotePort)
}

// 工具函数
// -----------------------------

func (c *Client) addListener(l net.Listener) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.listeners = append(c.listeners, l)
}

func (c *Client) createListener(host string, port int) (net.Listener, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s:%d: %w", host, port, err)
	}
	c.addListener(listener)
	return listener, nil
}

func (c *Client) handleConnections(ctx context.Context, listener net.Listener, remoteHost string, remotePort int) error {
	go func() {
		<-ctx.Done()
		log.Printf("Closing listener on port %d", c.port)
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
				log.Printf("failed to accept local connection: %v", err)
				return err
			}

			connID := atomic.AddInt32(&connCount, 1)

			go func(local net.Conn) {
				remoteAddr := fmt.Sprintf("%s:%d", remoteHost, remotePort)
				localAddr := local.RemoteAddr().String()
				log.Printf("[Conn-%d] New connection from %s to remote %s", connID, localAddr, remoteAddr)

				defer func() {
					local.Close()
					log.Printf("[Conn-%d] Connection closed from %s to remote %s", connID, localAddr, remoteAddr)
				}()

				remote, err := c.client.Dial("tcp", remoteAddr)
				if err != nil {
					log.Printf("[Conn-%d] Failed to dial remote %s: %v", connID, remoteAddr, err)
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

	go func() {
		defer func() { done <- struct{}{} }()
		bytesIn = copyDataWithCount(conn1, conn2)
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		bytesOut = copyDataWithCount(conn2, conn1)
	}()

	select {
	case <-ctx.Done():
		conn1.Close()
		conn2.Close()
	case <-done:
		log.Printf("[Conn-%d] Connection finished. Bytes in: %d, Bytes out: %d",
			connID, bytesIn, bytesOut)
		return
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
