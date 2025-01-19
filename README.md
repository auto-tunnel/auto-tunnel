# Auto Tunnel

Auto Tunnel 是一个自动管理 SSH 隧道的服务程序，支持本地端口到远程端口的映射，以及远程端口到本地端口的映射。它可以自动保持 SSH 隧道的连接，并在断开时自动重连。

## 功能特点

- 支持本地到远程和远程到本地的端口映射
- 自动重连机制
- 支持多个隧道同时运行
- 支持从 SSH 配置文件读取主机配置
- 支持密码和密钥两种认证方式
- 提供 systemd 服务支持
- 支持 DEB 和 RPM 打包

## 安装

### 从源码安装

```bash
# 克隆仓库
git clone https://github.com/auto-tunnel/auto-tunnel.git
cd auto-tunnel

# 编译安装
make build
sudo make install
```

### 使用包管理器安装

#### DEB 包（Ubuntu/Debian）
```bash
# 下载 DEB 包
wget https://github.com/auto-tunnel/auto-tunnel/releases/download/v0.1/auto-tunnel_0.1_amd64.deb

# 安装
sudo dpkg -i auto-tunnel_0.1_amd64.deb
```

#### RPM 包（CentOS/RHEL）
```bash
# 下载 RPM 包
wget https://github.com/auto-tunnel/auto-tunnel/releases/download/v0.1/auto-tunnel-0.1-1.x86_64.rpm

# 安装
sudo rpm -i auto-tunnel-0.1-1.x86_64.rpm
```

## 配置

配置文件默认按以下顺序查找：
1. 命令行指定的配置文件路径（-c 或 --config 参数）
2. 当前目录：`./config.yaml`
3. 系统配置目录：`/etc/auto-tunnel/config.yaml`
4. 用户主目录：`$HOME/.auto-tunnel/config.yaml`

### 配置文件示例

```yaml
servers:
  - name: "example-server"      # 服务器名称
    host: "remote-host"         # 远程主机地址（支持 ~/.ssh/config 中的主机名）
    port: 22                    # SSH 端口
    user: "username"            # SSH 用户名
    auth_method: "key"          # 认证方式：key 或 password
    key_path: "~/.ssh/id_rsa"   # SSH 密钥路径（使用 key 认证时必需）
    password: ""                # SSH 密码（使用 password 认证时必需）
    timeout: 3                  # 连接超时时间（秒）
    tunnels:
      - name: "mysql"           # 隧道名称
        type: "remote_to_local" # 隧道类型：remote_to_local 或 local_to_remote
        local_port: 3307        # 本地端口
        remote_port: 3306       # 远程端口
        remote_host: "localhost" # 远程主机
```

## 使用方法

### 命令行运行

```bash
# 使用默认配置文件路径
auto-tunnel

# 指定配置文件
auto-tunnel -c /path/to/config.yaml
# 或
auto-tunnel --config /path/to/config.yaml
```

### 作为系统服务运行

```bash
# 启动服务
sudo systemctl start auto-tunnel

# 设置开机自启
sudo systemctl enable auto-tunnel

# 查看服务状态
sudo systemctl status auto-tunnel

# 查看日志
sudo journalctl -u auto-tunnel -f
```

## 开发

### 依赖

- Go 1.18 或更高版本
- make
- dpkg-dev (用于构建 DEB 包)
- rpm-build (用于构建 RPM 包)

### 构建命令

```bash
# 运行程序
make run

# 构建程序
make build

# 构建 DEB 包
make build-deb

# 构建 RPM 包
make build-rpm

# 清理构建文件
make clean
```

## 日志

服务运行日志位于：
- 标准输出：`/var/log/auto-tunnel/auto-tunnel.log`
- 错误输出：`/var/log/auto-tunnel/error.log`

## 注意事项

1. 确保 SSH 密钥或密码配置正确
2. 确保目标端口未被其他程序占用
3. 确保有足够的权限访问配置文件和日志目录
4. 在生产环境中建议使用密钥认证而不是密码认证
5. 如果使用 SSH 配置文件中的主机名，确保 `~/.ssh/config` 文件权限正确

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request！如果您发现了 bug 或有新功能建议，请创建 Issue 进行讨论。

