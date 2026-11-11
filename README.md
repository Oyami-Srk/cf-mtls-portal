# cf-mtls-portal

使用 Rust 编写的 Cloudflare mTLS 客户端证书签发与管理服务。页面只包含签发、下载、安装说明和证书列表，不依赖某个具体应用。

后端使用 Axum、SQLite 和 OIDC；浏览器通过 WebCrypto 生成 RSA 2048 密钥，只向服务端提交 CSR。下载的 `.p12` 在浏览器本地加密，私钥和导入密码不上传。

## 功能

- OIDC 授权码登录，PKCE S256、state、nonce、签名、issuer、audience、UserInfo subject 校验。
- 按账号与组授权，验证新近认证及配置的 MFA `amr` 声明。
- 每台设备独立证书；支持续签、撤销、签发结果核对与开通重试。
- 只更新配置指定的 Zone、规则和域名，拒绝覆盖外部修改。
- 已确认的设备与规则状态保存在 SQLite；进程重启不会自动重复签发证书。
- 静态页面与锁定版本的浏览器依赖嵌入二进制，无需 Node.js 运行时。

## 本地构建

需要 Rust 1.95.0。工具链由 `rust-toolchain.toml` 固定。

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked
```

## 配置

从 `config.example.toml` 复制为 `config.toml`，填写 OIDC、Zone、规则和受保护域名。相对路径以配置文件所在目录为基准。

OIDC 客户端配置：

- 回调精确为 `https://你的领证域名/auth/callback`。
- scopes 为 `openid profile groups`，授权码模式、`client_secret_basic`、强制 PKCE S256。
- 身份中心对管理组要求 MFA；应用同时要求 `amr` 中包含 `mfa`，缺失时拒绝登录。
- discovery、JWKS、授权、token、userinfo 端点必须与 issuer 同源；跨域端点不受支持。
- 不要把身份中心和领证域名加入本应用管理的 mTLS 规则，避免首次领证死锁。

OIDC 客户端密钥放在 `oidc_secret_file` 指定的独立文件中，Linux 文件权限必须为 `0600` 或更严格。Cloudflare Token **仅从 `CLOUDFLARE_API_TOKEN` 环境变量读取**，在 Rust 中使用 `secrecy::SecretString` 持有；不会提供网页修改接口，也不会保存到数据库或配置文件。

Cloudflare Token 只授权目标 Zone 的 `SSL and Certificates: Edit` 与 `Zone WAF: Edit`。Cloudflare 的 Token 权限通常只能限制到 Zone，无法限制到本项目的一条规则；代码中的固定目标检查不能替代 Token 自身的权限边界。

```sh
./target/release/cf-mtls-portal check-config config.toml
# 由服务管理器或容器运行时注入 CLOUDFLARE_API_TOKEN，不写入命令行参数。
./target/release/cf-mtls-portal serve config.toml
```

## Docker

镜像：`shiroko/cf-mtls-portal`。支持 `linux/amd64`。`master` 提交通过 CI 后发布 `latest`、`master` 和 `sha-<完整提交 SHA>`；生产部署推荐使用发布结果中的不可变 digest。

参考 `compose.yml`。容器内配置应设置：

```toml
listen = "0.0.0.0:8080"
data_dir = "/data"
oidc_secret_file = "/secrets/oidc-client-secret"
```

宿主机创建数据目录并赋予容器 UID/GID `10001:10001`，只将端口绑定到 loopback，由 HTTPS 反向代理提供入口。`CLOUDFLARE_API_TOKEN` 应由部署平台或权限受限的环境文件注入。不要运行会展开并输出密钥的 `docker compose config`；校验使用 `docker compose config --quiet`。

`deploy/nginx.conf.example` 提供反代示例：仅转发应用自己的 Cookie，覆盖客户端传入的转发头，日志使用不含查询参数的 `$uri`，避免记录 OIDC code/state。`trusted_proxies` 必须仅包含实际可信代理 IP。

环境变量仍可被有权限读取进程环境或 Docker 配置的管理员取得。`secrecy` 降低 Rust 代码中意外打印、序列化和释放后残留的风险，不能隐藏宿主机上的环境变量，也不能擦除 HTTP 客户端必需的所有临时副本。

## 旧版数据迁移

不要把新程序直接指向旧服务正在使用的数据库。

1. 停止旧服务，或通过 SQLite 在线备份得到一致的离线副本。保留旧数据、配置和镜像。
2. 使用新的空数据目录，执行：

   ```sh
   cf-mtls-portal import-legacy /backup/metadata.sqlite3 /new-data/metadata.sqlite3
   ```

3. 导入会校验完整性、设备 ID、状态和指纹，使用 SQLite backup API；目标已存在则拒绝覆盖。新数据库标记 `user_version=1`。
4. 保持原 issuer、OIDC client ID、客户端密钥及用户的稳定 `sub`，否则旧设备可能无法归属于原账号。
5. 迁移 `expected_rule` 和所有设备记录；按实际现场填写原 Zone、规则、域名与保留证书。不要将示例的全零指纹用于生产。
6. 候选实例验证后再切换入口。应用重启使本应用会话失效；无需重置身份中心的密码或 MFA。

已有设备证书在应用停机期间仍由 Cloudflare 原有规则控制，停止领证服务不会自动撤销证书。

## 失败与恢复

- 签发 POST 不自动重试。网络结果不确定时在列表中“核对结果”，仅接受同一 CN 和 SPKI 的唯一证书。
- 证书已签发、规则尚未确认时“重试开通”，不会重新申请证书；会重新核对远端证书仍有效。
- 撤销先持久化待撤销状态，再从规则中移除指纹，最后撤销远端证书。未完成时保留状态，允许重试。
- 规则写入前保存快照与持久化意图；只有远端已明确变成预期表达式且其他规则未变化时才确认成功。仍停留在旧表达式的超时操作不会自动重放。`pending_policy` 需要管理员结合 Cloudflare 状态和快照核对后处理，不要直接删除数据库保护状态。
- 页面关闭或刷新后无法找回未保存的私钥；需要撤销对应证书再重新领取。续签不自动撤销旧证书。

## CI 与发布

工作流检查格式、Clippy、单元/HTTP 边界测试、release 构建、浏览器脚本语法及 RustSec 公告。所有第三方 Actions 固定到完整 commit SHA。公开 PR 不获得 Docker Hub 凭据；仅 `master` 的 push 且检查成功后运行发布 job。

仓库需要 Actions Secrets：`DOCKERHUB_USERNAME`、`DOCKERHUB_TOKEN`。Token 仅需向 `shiroko/cf-mtls-portal` 推送的 Read & Write 权限，不需要 Delete。工作流不部署服务器；镜像发布与服务切换分开进行。

安全审查与已知限制见 [SECURITY.md](SECURITY.md)。浏览器依赖来源和校验值见 [THIRD_PARTY.md](THIRD_PARTY.md)。
