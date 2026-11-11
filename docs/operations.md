# 配置、运行与数据迁移

## 配置

从根目录 `config.example.toml` 复制为 `config.toml`。相对文件路径以配置文件所在目录为基准。

OIDC 客户端要求：

- 精确回调 `https://你的领证域名/auth/callback`。
- scopes 为 `openid profile groups`，授权码模式、`client_secret_basic`、PKCE S256。
- 身份中心对管理组要求 MFA；应用要求配置的 `amr` 声明（通常为 `mfa`），缺失时拒绝登录。
- discovery、JWKS、授权、token、userinfo 必须与 issuer 同源。
- 不要把身份中心和领证域名加入受本应用管理的 mTLS 规则，避免首次领证死锁。

OIDC secret 放在 `oidc_secret_file` 指定的只读文件中，Linux 权限为 `0600` 或更严格。Cloudflare Token 由环境变量 `CLOUDFLARE_API_TOKEN` 注入，使用 `secrecy::SecretString` 持有，不提供网页修改接口。

Token 只授权目标 Zone 的 `SSL and Certificates: Edit` 与 `Zone WAF: Edit`。该权限通常大于一条规则；应用内的目标限制不能约束已取得 Token 的其他程序。

```sh
cf-mtls-portal check-config config.toml
# 由服务管理器或容器运行时注入 Token，不放进命令行参数。
cf-mtls-portal serve config.toml
```

## 容器与反代

根目录 `compose.yml` 是通用运行示例。容器内配置：

```toml
listen = "0.0.0.0:8080"
data_dir = "/data"
oidc_secret_file = "/secrets/oidc-client-secret"
```

数据目录需允许 UID/GID `10001:10001` 访问，宿主机端口仅绑定 loopback，由 HTTPS 反向代理提供入口。生产镜像应固定 digest。检查 Compose 时使用 `docker compose config --quiet`，避免展开输出真实 Token。

反向代理应覆盖客户端传入的身份/转发头，只转发应用自己的 Cookie，避免将 OIDC 回调查询参数写入日志。`trusted_proxies` 只配置实际可信代理 IP；日志可记录不带 query 的 URI。

环境变量仍可被进程或 Docker 管理员读取；`secrecy` 不负责隐藏 OS 环境或所有 HTTP 库临时副本。详情见 [SECURITY.md](../SECURITY.md)。

## 显式导入旧数据

1. 停止旧服务，或通过 SQLite 在线备份得到一致的离线副本；保留原配置、数据和镜像。
2. 使用新的空目录：

   ```sh
   cf-mtls-portal import-legacy /backup/metadata.sqlite3 /new-data/metadata.sqlite3
   ```

3. 导入使用 SQLite backup API，校验完整性、设备 ID、状态和指纹，目标存在则拒绝覆盖。新数据库标记 `user_version=1`。
4. 保持原 issuer、client ID、客户端密钥和用户稳定 sub，保留全部设备及 `expected_rule`。不要用示例的全零指纹替换真实状态。
5. 候选验证通过后再切换入口，实际完成 SSO/MFA、签发、安装和权限回归。应用重启会清除本应用的 RAM 会话，不需要重置身份中心密码或 MFA。

## 失败与恢复

- 签发 POST 不自动重试；不确定时按原 CN/SPKI 核对唯一结果。
- 已签发但未确认规则时“重试开通”，不重新申请证书，并重新检查远端状态。
- 撤销先保存待撤销状态，再从规则排除指纹，最后撤销远端证书。失败时保留状态并允许重试。
- 规则修改有快照和持久化意图。只有确认远端是目标表达式且其他规则未变化才完成；仍是旧表达式不代表未知请求已结束，不自动重放。管理员应结合快照与远端状态处理 `pending_policy`，不能直接删除保护状态。
- 关闭或刷新页面无法找回未保存的私钥。应撤销对应证书后重新领取；续签不会自动撤销旧证书。
- 停止领证服务不会自动撤销已有设备证书；它们继续由 Cloudflare 原有规则控制。
