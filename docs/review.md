# 代码审阅入口

从入口和权限边界开始读；业务代码保持普通 Rust 模块与浏览器原生 ES 模块，没有额外框架层或生成代码。

## 目录

```text
src/
  main.rs                 CLI 命令、启动、关闭
  http/
    mod.rs                路由表与请求上限
    middleware.rs         Host、会话、CSRF、速率限制、安全响应头
    login.rs              OIDC 跳转与回调的 HTTP 适配
    api.rs                证书、设备和会话 API
    assets.rs             嵌入静态资源的显式白名单
  auth/
    mod.rs                OIDC discovery、PKCE、state/nonce、声明验证
    session.rs            Cookie、会话时限、CSRF、退出
    transport.rs          同源出站 HTTP、响应大小上限、密钥文件读取
    tests.rs              OIDC 与会话边界测试
  cloudflare.rs           固定 API 目标、规则表达式、远端写入确认
  crypto.rs               CSR 与签发证书校验
  store.rs                SQLite、状态、额度、离线导入
  state.rs                应用依赖、申请缓存与锁
  error.rs                不泄漏凭据的错误响应
  tests.rs                配置、存储、CSR 和 HTTP 回归测试
web/
  index.html              语义化表单与 Bulma 响应式布局
  assets/
    css/app.css           少量应用特有样式
    js/
      app.mjs             页面控制与事件绑定
      api.mjs             唯一的 fetch 入口
      certificates.mjs    浏览器密钥、CSR、PKCS#12；无网络请求
      devices.mjs         列表渲染；用户内容只写 textContent
      install.mjs         多端安装说明
    vendor/               锁定发布物、许可证、来源和摘要 manifest
  tests/                  Node 内置 runner，无额外 npm 依赖
tests/fixtures/           仅公开 CSR/证书，无私钥
```

## 推荐阅读顺序

1. `http/mod.rs` 和 `http/middleware.rs`：确认哪些入口公开、写 API 在哪里做会话和 CSRF 检查。
2. `auth/mod.rs`、`auth/session.rs`、`auth/transport.rs`：确认 OIDC 与会话边界、MFA、出站请求限制。测试在 `auth/tests.rs`。
3. `http/api.rs`：按签发、核对、重试、撤销读状态转换，特别是每次查库的 owner 条件。
4. `crypto.rs`：检查 CSR 与返回证书的公钥、主题、算法及用途约束。
5. `cloudflare.rs` 和 `store.rs`：检查规则漂移、未知远端写入、撤销竞态与重启后的状态。
6. `web/assets/js/certificates.mjs` 与 `api.mjs`：前者持有私钥，不发送请求；后者只接受同源 API 路径，不接触私钥。`app.mjs` 只传递名字、申请标识和公开 CSR。
7. `SECURITY.md`：阅读信任边界、已审查的 RSA 公告例外及剩余限制。

## 改动时的约束

- 不把 Token 或设备私钥加入配置、日志、错误消息、API 响应或测试快照。
- 不通过 UI 状态代替服务端鉴权，不通过存在 Authorization 头来放行。
- 不自动重放结果不确定的签发或规则更新。
- 增加静态资源必须加入 `http/assets.rs`；不增加任意文件读取路由。
- 更新第三方发布物时核对 `web/assets/vendor/manifest.json`、许可证和 HTML SRI；压缩 vendor 文件按上游摘要审阅，不和应用代码混在一起。
- 布局、断点和标准控件优先使用 Bulma 类；避免重新手写一套 CSS 组件。
- 浏览器业务代码使用原生模块，不需要 npm install、Node 服务、打包器或转译器。Node 仅用于 CI 语法检查和内置测试。

## 验证命令

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked
node --test web/tests/*.test.mjs
```

配置和运行步骤见 [operations.md](operations.md)；CI 与发布定义在 `.github/workflows/ci.yml`，其中没有服务器部署步骤。
