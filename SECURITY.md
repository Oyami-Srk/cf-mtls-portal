# 安全审查

审查范围：本仓库的 Rust HTTP/OIDC/CSR/SQLite/Cloudflare 代码、浏览器签发与 PKCS#12 打包、容器配置和 GitHub Actions。该记录是代码审查和验证结论，不是“绝对不会被攻破”的保证，也不是独立第三方渗透测试报告。

## 信任边界

网络客户端不可信。身份中心及其管理员、配置文件写入者、Cloudflare 账号管理员、Docker/宿主机管理员、`master` 写入者属于可信权限主体。取得这些主体权限的人可以影响认证、签发或部署；Rust 和 `secrecy` 不能消除这些权限本身。

只有同时满足允许账号、指定管理组、新近认证和 MFA 声明的用户可以签发。每条设备记录按稳定 OIDC `sub` 检查归属。授予签发权限意味着允许该身份把新设备加入配置的 mTLS 规则，必须保护身份中心账号。

## 审查及修复

| 边界 | 检查和处理 |
|---|---|
| OIDC 伪造与重放 | 标准库验证签名、issuer、audience、nonce、at_hash 与 UserInfo subject；仅 RS256/PS256/ES256；强制 PKCE S256、一次性 state/cookie 绑定，失败回调也消耗 flow；拒绝缺少新近 auth_time 或 MFA 的登录。 |
| SSRF 与凭据外泄 | 仅使用配置的 issuer 和固定 Cloudflare API；每次 OIDC HTTP 请求检查同源，禁用重定向和系统代理，限制连接/响应超时与响应大小；不接受用户提交的远端 URL。 |
| CSRF 与会话 | 所有写 API 要求精确 Origin、随机 CSRF Token、same-origin Fetch Metadata；Host 固定；Secure/HttpOnly/SameSite=Lax 的 host-only Cookie；重复 Cookie 拒绝；会话 30 分钟绝对、10 分钟闲置有效期，RAM 有上限。 |
| 横向越权 | CSR 申请、证书查询、续签、恢复、撤销均以会话 sub 查库；转发身份头或 Authorization 头不能代替会话。 |
| 恶意 CSR | 输入上限、单一 CN、固定申请主题、公钥 RSA 2048/e65537、SHA256 签名验证、版本和空 attributes 检查；拒绝私钥 PEM、附加 PEM、尾随 DER。 |
| 签发结果替换 | 远端返回证书必须是当前 CSR 的 SPKI 和主题；有效期合理、非 CA、clientAuth EKU、digitalSignature KU；不匹配则不更新访问规则。 |
| 规则漂移与并发 | 单进程写锁、数据目录文件锁、预读/重读、规则快照、其他规则哈希、写后核对。表达式归一化保留引号内空白，避免把不同字符串视为相同。 |
| 超时、崩溃及重复签发 | 签发 POST 禁止自动重试；先保存申请公钥哈希。规则写入前记录持久化意图；若仍观察到旧表达式，不能判定远端请求结束，因此保留阻断状态，不盲目重放。 |
| 撤销竞态 | 先持久化 revocation_pending，使其他更新不再加入该证书；确认从规则排除后才标记 blocked，再撤销 Cloudflare 证书。网络失败和进程重启保留待处理状态。 |
| XSS 与浏览器私钥 | 仅 textContent 构造用户内容，严格 CSP、无第三方 CDN、无 inline/eval、禁止 framing；密钥只在本页 RAM 中生成，不用 localStorage/IndexedDB/Service Worker；离页提示、可核对签发结果后重打包，避免重复提交覆盖未保存密钥。 |
| Token 与日志 | Cloudflare 环境变量使用 secrecy::SecretString；无网页写 Token 接口、无密钥序列化；错误日志仅记录静态 code，不打印请求、OIDC Token、CSR 或远端响应；反代示例不记录 query。 |
| 资源与文件 | 请求 16 KiB、URI 4 KiB、128 并发、IP/账号速率限制、登录/申请缓存上限、签发额度；SQLite 参数化、FULL 同步、单实例锁，Linux 数据目录 0700、文件 0600；独立非 root 容器、只读根目录、无 Docker socket。 |
| 供应链 | Cargo.lock、固定 Rust 与基础镜像 digest、Actions commit SHA、浏览器 vendor 校验值；发布只从通过 CI 的 master 触发，不把真实凭据传给 PR 或镜像 build args。 |

## RustSec 公告的明确例外

`openidconnect 4.1.0` 间接使用 `rsa 0.9.10`，命中 [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html) / CVE-2023-49092。修复版本为 rsa >= 0.10，但上游当前依赖约束仍为 0.9。

该公告针对 RSA **私钥操作**的可观察时序泄漏。本程序使用该依赖验证身份中心的公开签名；不在服务器生成、导入、解密或签名 RSA 私钥。设备私钥由浏览器 WebCrypto 生成，不进入 Rust 进程。OIDC 客户端使用 client_secret_basic，不使用 RSA private_key_jwt。因此在当前代码路径中，该私钥泄漏攻击不可达。

CI 保留原始 audit JSON，同时只对该公告 ID 使用明确例外，其他漏洞仍导致失败。没有把扫描结果表述为零漏洞。若后续引入服务端 RSA 私钥功能，该例外立即失效；应先升级上游或更换实现。仅更新版本号、使用宽泛 ignore 或隐藏 audit 输出不能视为修复。

## 剩余限制

- `secrecy` 不能隐藏 OS/Docker 环境变量。读取进程环境、Docker inspect、调试器、core dump 或宿主机内存的权限必须受控；真实部署可禁用 core dump。HTTP/OIDC 库仍需要临时凭据副本。
- 页面是私钥生成与导出的受信任程序；浏览器、扩展、前端静态资源或宿主机被控制时，可窃取私钥。CSP/SRI/固定依赖降低风险，不能抵御已控制的终端。
- `.p12` 是可复制的加密私钥文件，密码使用 AES-256/PBKDF2 100000 迭代保护；它不是硬件绑定、不可导出的安全模块身份。下载文件和密码应单独保管。
- Cloudflare Token 的真实权限大于单条规则，应用内限制不能约束已取得该 Token 的其他程序。
- Cloudflare API 不提供本程序可依赖的原子 CAS；不能在应用写规则的同时手工修改同一规则。检测到变化时会停止，极短竞争窗口仍属于 API 的外部限制。
- 规则更新和证书撤销在 Cloudflare 边缘传播并非瞬时。已建立连接、边缘缓存与应用自己的登录会话有各自的生命周期。
- 撤销管理组不会立即结束应用已有的 RAM 会话，最长受 30 分钟绝对时限限制；必要时重启本应用清除会话。
- 请求体、速率和资源上限不是 DDoS 防护；反向代理、网络隔离、内网领证和身份中心安全仍然必要。
- debug 构建可显式允许 loopback HTTP 以验证界面；release 构建拒绝该模式。它不跳过 OIDC 或 CSRF。
- 单元测试与本地验证不能替代实际 OIDC、Cloudflare 签发、手机安装及代理配置的部署验收。未经该环境验证的路径应如实标为未验证。

## 报告问题

请在仓库 Security Advisories 中私下报告漏洞，不要在公开 Issue 中上传 Token、私钥、会话 Cookie 或含真实凭据的日志。
