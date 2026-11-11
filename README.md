# cf-mtls-portal

Rust 编写的 Cloudflare mTLS 客户端证书签发与管理服务。

通过 OIDC 和 MFA 登录，为每台设备签发、下载、续签或撤销证书。私钥由浏览器 WebCrypto 生成，只上传公开 CSR；`.p12` 在浏览器本地加密。受保护域名由配置决定，不固定为某个应用。

## 结构与审阅

| 目录 | 职责 |
|---|---|
| `src/http/` | 路由、鉴权中间件、HTTP API、静态资源白名单 |
| `src/auth/` | OIDC 协议、会话与 CSRF、受限出站请求 |
| `src/cloudflare.rs` / `crypto.rs` / `store.rs` | 规则更新、证书校验、SQLite 状态 |
| `web/assets/js/` | 原生 ES 模块：页面、API、证书处理、列表与安装说明 |
| `web/assets/css/` | 少量应用特有样式，布局与控件由 Bulma 提供 |
| `web/assets/vendor/` | 固定版本发布物、许可证与摘要清单 |
| `web/tests/` / `src/tests.rs` | 前端密码学与后端边界测试 |

推荐阅读顺序及安全边界见 [代码审阅指南](docs/review.md)。配置、运行、迁移和失败恢复见 [运行说明](docs/operations.md)。威胁模型及公告例外见 [SECURITY.md](SECURITY.md)。

## 构建与验证

工具链固定为 Rust 1.95.0：

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked
node --test web/tests/*.test.mjs
```

前端使用 Bulma 的预编译 CSS 和原生 ES 模块，**无需 npm install、Node 服务、打包器或转译器**。Node 仅用于 CI 语法检查和内置测试。页面、模块及依赖都嵌入 Rust 二进制，由同源入口提供。

## 配置与启动

复制 `config.example.toml` 为 `config.toml`，填写 OIDC、Cloudflare Zone、规则与域名。

- Cloudflare Token 仅从环境变量 **`CLOUDFLARE_API_TOKEN`** 读取，使用 **`secrecy::SecretString`** 持有，不提供网页修改接口。
- OIDC secret 使用 `oidc_secret_file` 指定的独立只读文件。
- Token 仅授权目标 Zone 的 `SSL and Certificates: Edit`、`Zone WAF: Edit`。
- 回调为 `https://你的领证域名/auth/callback`，使用授权码、PKCE S256、`client_secret_basic` 及 MFA 声明校验。

```sh
cf-mtls-portal check-config config.toml
# 由服务管理器注入 Token，不放在命令行参数中。
cf-mtls-portal serve config.toml
```

容器运行参考根目录 `compose.yml`。镜像为 `shiroko/cf-mtls-portal`，支持 `linux/amd64`；生产应固定 digest。详细文件权限、反代边界和旧数据导入步骤见 [运行说明](docs/operations.md)。

## CI 与发布

PR 和 `master` 提交检查格式、Clippy、Rust/浏览器模块测试、release、脚本语法与 RustSec 公告。Actions 固定完整 commit SHA；PR 不取得发布凭据。

`master` push 检查成功后发布 Docker Hub 的 `latest`、`master` 和 `sha-<完整提交 SHA>`。需要 Actions Secrets：`DOCKERHUB_USERNAME`、`DOCKERHUB_TOKEN`。工作流只发布镜像，不部署服务器。

第三方发布物来源、许可证、摘要和 SRI 见 [THIRD_PARTY.md](THIRD_PARTY.md)。
