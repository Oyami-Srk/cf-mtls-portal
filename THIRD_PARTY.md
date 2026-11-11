# 浏览器依赖

## node-forge 1.4.3

`web/assets/vendor/forge.min.js` 来自官方 npm 包 `node-forge@1.4.3` 的 `dist/forge.min.js`。它只在浏览器中用于 CSR 的 ASN.1 编码与 PKCS#12 封装；生产后端不运行 JavaScript 或 Node.js。

- 官方源码：https://github.com/digitalbazaar/forge
- npm 包：https://www.npmjs.com/package/node-forge/v/1.4.3
- 包 tarball integrity：`sha512-P6wzfh6t70avmV8FrVEAd/36sOPJQ+hkaJVX1Laap9J/77m7M0eyozDvc8SwnDf4P7MP94gwbAAo0rg3YVXT+g==`
- vendored JS SHA256：`a8b6d50267d709db0411a598efc4c57bffd6127f21410339f71c919e3bde725b`
- 许可证副本：`web/assets/vendor/LICENSE.node-forge`（BSD-3-Clause / GPL-2.0 双许可，使用 BSD 条款）。

## Bulma 1.0.4

`web/assets/vendor/bulma.min.css` 是官方 npm 发布包的预编译 CSS，直接提供响应式布局、表单、按钮、表格、间距和深浅色主题。只提取 CSS 与许可证，没有安装 Sass/PostCSS 或执行包中的任何脚本。

- 官方源码：https://github.com/jgthms/bulma
- 文档：https://bulma.io/documentation/
- 发布物：https://registry.npmjs.org/bulma/-/bulma-1.0.4.tgz
- 包 tarball integrity：`sha512-Ffb6YGXDiZYX3cqvSbHWqQ8+LkX6tVoTcZuVB3lm93sbAVXlO0D6QlOTMnV6g18gILpAXqkG2z9hf9z4hCjz2g==`
- CSS SHA256：`67fa26df1ca9e95d8f2adc7c04fa1b15fa3d24257470ebc10cc68b9aab914bee`
- MIT 许可证副本：`web/assets/vendor/LICENSE.bulma`。

## 更新与验证

HTML 的 vendor script 和 stylesheet 使用 SRI。`web/assets/vendor/manifest.json` 保存机器可读的版本、来源与摘要；`node --test web/tests/*.test.mjs` 校验 vendored 字节、HTML SRI、许可证，以及证书打包兼容性。更新时同时复查发布物、漏洞公告、摘要和许可证，不从任意 CDN 动态加载。

`tests/fixtures/client.csr` 和 `client.pem` 是专门生成的公开测试材料，无生产用途、不作为受信任 CA；生成用的私钥没有保存到仓库。
