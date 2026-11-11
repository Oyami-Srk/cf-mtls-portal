const instructions = {
  android: [
    "下载 .p12 文件。",
    "在系统设置中搜索“安装证书”，选择“VPN 和应用”等客户端身份选项，导入文件并输入导入密码。不要选择安装 CA 证书。",
    "使用支持客户端证书的浏览器访问 mTLS 入口，按提示选择证书。部分应用内浏览器不支持。",
  ],
  ios: [
    "使用 Safari 下载 .p12 文件，保存到“文件”。",
    "打开该文件，按系统提示前往“设置”，安装下载的客户端身份并输入导入密码。无需安装根 CA。",
    "使用 Safari 访问 mTLS 入口，选择对应的设备证书。",
  ],
  windows: [
    "下载并双击 .p12 文件。",
    "在导入向导中选择“当前用户”，输入导入密码，将证书导入“个人”证书库。无需设置为可导出或安装根 CA。",
    "使用 Edge 或 Chrome 访问 mTLS 入口，选择对应的设备证书。",
  ],
  mac: [
    "下载 .p12 文件并用“钥匙串访问”打开。",
    "将身份导入“登录”钥匙串，输入导入密码。无需设置为受信任的根 CA。",
    "使用 Safari 等支持系统客户端身份的浏览器访问 mTLS 入口。",
  ],
};

export function currentDeviceType() {
  const agent = navigator.userAgent;
  if (/Android/i.test(agent)) return "android";
  if (/iPhone|iPad/i.test(agent)) return "ios";
  if (/Win/i.test(agent)) return "windows";
  return "mac";
}

export function renderInstallGuide(type) {
  document.getElementById("install-steps").replaceChildren(
    ...instructions[type].map(text => {
      const item = document.createElement("li");
      item.textContent = text;
      return item;
    }),
  );
}
