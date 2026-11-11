# 浏览器依赖

`web/vendor/forge.min.js` 来自官方 npm 包 `node-forge@1.4.3` 的 `dist/forge.min.js`。它只在浏览器中用于 CSR 的 ASN.1 编码与 PKCS#12 封装；生产后端不运行 JavaScript 或 Node.js。

- 官方源码：https://github.com/digitalbazaar/forge
- npm 包：https://www.npmjs.com/package/node-forge/v/1.4.3
- 包 tarball integrity：`sha512-P6wzfh6t70avmV8FrVEAd/36sOPJQ+hkaJVX1Laap9J/77m7M0eyozDvc8SwnDf4P7MP94gwbAAo0rg3YVXT+g==`
- vendored JS SHA256：`a8b6d50267d709db0411a598efc4c57bffd6127f21410339f71c919e3bde725b`
- 许可证副本：`web/vendor/LICENSE.node-forge`（BSD-3-Clause / GPL-2.0 双许可，使用 BSD 条款）。

HTML 的 vendor script 使用 SRI。更新时同时复查发布物、漏洞公告、校验值、许可证、SRI 及 PKCS#12 导入兼容性，不从任意 CDN 动态加载。

`tests/fixtures/client.csr` 和 `client.pem` 是专门生成的公开测试材料，无生产用途、不作为受信任 CA；生成用的私钥没有保存到仓库。
