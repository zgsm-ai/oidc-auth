# OIDC Authentication Server

一个基于 Casdoor 的 OIDC 认证服务器，提供用户认证和授权功能。

## 功能特性

- 🔐 基于 OIDC 协议的用户认证
- 🌟 GitHub Star 同步功能
- 📱 自定义短信发送
- 🗄️ 支持 MySQL 和 PostgreSQL 数据库
- 🐳 Docker 容器化部署
- 📊 健康检查和监控


## 快速开始

### 环境要求

- Go 1.23.0+
- MySQL 8.0+ 或 PostgreSQL 13+
- Docker (可选)

### 安装部署

1. **克隆项目**
```bash
git clone https://github.com/zgsm-ai/oidc-auth.git
cd oidc-auth
```

2. **安装依赖**
```bash
go mod tidy
```

3. **运行服务**
```bash
go run cmd/main.go serve --config config/config.yaml
```

### Docker 部署

1. **构建镜像**
```bash
docker build -t oidc-auth:latest .
```

2. **运行容器**
```bash
docker run -d \
  --name oidc-auth \
  -p 8080:8080 \
  -v $(pwd)/config:/app/config \
  -e DATABASE_PASSWORD=your_password \
  -e AUTH_CLIENT_SECRET=your_secret \
  -e GITHUB_STAR_PERSONNEL_TOKEN=your_token \
  oidc-auth:latest
```

### Docker Compose

```bash
# 启动完整服务栈（包括数据库）
docker-compose up -d
```

## 配置说明

### 环境变量

| 变量名 | 描述 | 默认值 |
|--------|------|--------|
| `SERVER_PORT` | 服务端口 | 8080 |
| `SERVER_SESSION_SECRET` | Session 密钥 | - |
| `DATABASE_HOST` | 数据库主机 | localhost |
| `DATABASE_PORT` | 数据库端口 | 5432 |
| `DATABASE_USERNAME` | 数据库用户名 | - |
| `DATABASE_PASSWORD` | 数据库密码 | - |
| `AUTH_CLIENT_ID` | OIDC 客户端ID | - |
| `AUTH_CLIENT_SECRET` | OIDC 客户端密钥 | - |
| `GITHUB_STAR_PERSONNEL_TOKEN` | GitHub Token | - |

### 配置文件

主要配置文件位于 `config/config.yaml`，包含以下配置段：

- `server`: 服务器配置
- `log`: 日志配置
- `auth`: 认证配置
- `database`: 数据库配置
- `github_star`: GitHub 同步配置

## API 接口

### 认证相关
- `GET /oidc_auth/plugin/login` - 用户登录
- `GET /oidc_auth/plugin/login/callback` - 登录回调
- `GET /oidc_auth/plugin/login/logout` - 用户退出
- `GET /oidc_auth/plugin/login/status` - 登录状态
- `GET /oidc_auth/plugin/login/token` - 获取令牌

## 开发指南
### 项目结构

```
├── cmd/                 # 应用入口
├── internal/           # 内部模块
│   ├── config/        # 配置管理
│   ├── handler/       # HTTP 处理器
│   ├── middleware/    # 中间件
│   ├── services/      # 业务服务
│   └── repository/    # 数据访问层
├── pkg/               # 公共包
│   ├── log/          # 日志工具
│   └── utils/        # 工具函数
├── config/           # 配置文件
└── charts/          # Helm 图表
```

### 开发命令

```bash
# 运行服务
make dev

# 构建二进制
make build

# 运行测试
make test

# 代码格式化
make fmt

# 代码检查
make lint

# 设置开发环境
make setup
```

## 部署选项

### 1. 单机部署
```bash
# 直接运行
go run cmd/main.go serve

# 或使用二进制
./bin/oidc-auth serve --config config/config.yaml
```

### 2. Docker 部署
```bash
docker run -d \
  -p 8080:8080 \
  -e DATABASE_PASSWORD=password \
  zgsm-ai/oidc-auth:latest
```

### 3. Kubernetes 部署

使用改进的 Helm Charts 部署到 Kubernetes：

```bash
# 创建命名空间
kubectl create namespace oidc-auth

# 创建 Secrets
kubectl create secret generic oidc-auth-secrets \
  --from-literal=session-secret="your-very-long-session-secret" \
  --from-literal=client-id="your-oidc-client-id" \
  --from-literal=client-secret="your-oidc-client-secret" \
  -n oidc-auth

kubectl create secret generic postgres-secrets \
  --from-literal=password="your-database-password" \
  -n oidc-auth

# 准备配置文件
cp charts/values-example.yaml charts/values.yaml
# 编辑 charts/values.yaml 文件

# 安装 Helm Chart
helm install oidc-auth ./charts \
  -n oidc-auth \
  -f charts/values.yaml

# 生产环境部署（带自动伸缩）
helm install oidc-auth ./charts \
  -n oidc-auth \
  -f charts/values.yaml \
  --set replicaCount=3 \
  --set autoscaling.enabled=true \
  --set resources.requests.memory=512Mi
```

**🔗 详细部署指南**: 查看 [Helm Charts 文档](charts/README.md)

## 监控和维护

### 健康检查
```bash
# 完整健康检查
curl http://localhost:8080/health

# 就绪检查
curl http://localhost:8080/ready

# 存活检查  
curl http://localhost:8080/live
```

### 日志监控
```bash
# 查看应用日志
tail -f logs/app.log

# Docker 日志
docker logs -f oidc-auth
```

## 安全注意事项

⚠️ **重要提醒**：

1. 不要在配置文件中硬编码敏感信息
2. 使用环境变量或密钥管理系统存储敏感配置
3. 定期更换 Session 密钥和 API 密钥
4. 在生产环境中启用 HTTPS
5. 使用强密码和密钥（至少32字符）
6. 定期备份数据库
7. 监控异常登录活动

## 性能优化

- **数据库连接池**: 合理配置 `MaxIdleConns` 和 `MaxOpenConns`
- **会话配置**: 根据需求调整会话超时时间

## 故障排除

### 常见问题

1. **数据库连接失败**
   ```bash
   # 检查配置
   curl http://localhost:8080/health
   
   # 查看连接统计
   # 使用管理接口获取连接池状态
   ```

2. **认证失败**
   - 检查 Casdoor 配置
   - 验证客户端ID和密钥
   - 确认回调URL正确

3. **健康检查失败**
   - 检查数据库连接
   - 验证依赖服务状态

## 版本历史

- **v1.0.0** - 初始版本

详细变更记录请查看 [CHANGELOG.md](CHANGELOG.md)

## 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 贡献

欢迎提交 Issue 和 Pull Request！

### 贡献指南
1. Fork 项目
2. 创建特性分支
3. 提交变更
4. 推送到分支
5. 创建 Pull Request

## 支持

如有问题或建议，请创建 [Issue](https://github.com/zgsm-ai/oidc-auth/issues)。

## 相关文档

- [数据库改进文档](DATABASE_IMPROVEMENTS.md)
- [Go最佳实践改进报告](REFACTORING_IMPROVEMENTS.md)
- **[项目结构和代码质量改进](CODE_STRUCTURE_IMPROVEMENTS.md)**
- [变更日志](CHANGELOG.md)
- [使用示例](examples/database_usage.go)
- **[Helm Charts 部署指南](charts/README.md)**