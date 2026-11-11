import { ApiClient } from "./api.mjs";
import { BrowserCertificate, randomPassword } from "./certificates.mjs";
import { formatDate, renderDevices } from "./devices.mjs";
import { currentDeviceType, renderInstallGuide } from "./install.mjs";

const element = id => document.getElementById(id);
const deviceType = currentDeviceType();
let session;
let certificateRequest;
let renewalId;
let pendingRevoke;
let busy = false;

const api = new ApiClient(() => {
  // Keep unsaved key material available if a session expires during recovery.
  if (certificateRequest) return;
  element("workspace").hidden = true;
  element("login-panel").hidden = false;
  element("logout").hidden = true;
});

function notice(message, error = false) {
  const notice = element("notice");
  notice.textContent = message;
  notice.hidden = !message;
  notice.classList.toggle("has-text-danger", error);
}

function setBusy(value, message = "") {
  busy = value;
  element("issue-button").disabled = value || !session?.configured || Boolean(certificateRequest);
  element("progress").hidden = !value;
  element("progress").textContent = message;
  element("clear-request").disabled = value;
  element("logout").disabled = value || Boolean(certificateRequest);
  for (const button of document.querySelectorAll(".device-actions button")) {
    button.disabled = value;
  }
}

function resetRequest() {
  certificateRequest?.dispose();
  certificateRequest = undefined;
  renewalId = undefined;
  element("enroll-form").reset();
  element("device-type").value = deviceType;
  element("import-password").type = "password";
  element("show-password").textContent = "显示密码";
  element("enroll-form").hidden = false;
  element("download-panel").hidden = true;
  element("clear-request").hidden = true;
  element("renew-note").hidden = true;
  element("enroll-title").textContent = "签发证书";
  renderInstallGuide(deviceType);
  setBusy(false);
}

function discardRequest() {
  if (certificateRequest && !confirm("确认清除本次申请的本机密钥？未保存的私钥将无法找回。已签发证书仍需在列表中撤销。")) {
    return false;
  }
  resetRequest();
  return true;
}

function beginRenewal(device) {
  if (certificateRequest && !discardRequest()) return;
  renewalId = device.id;
  element("device-name").value = device.name;
  element("enroll-title").textContent = "续签证书";
  element("renew-note").hidden = false;
  window.scrollTo({ top: 0, behavior: "auto" });
}

async function refreshDevices() {
  const result = await api.request("/api/devices");
  renderDevices(result, {
    isBusy: () => busy,
    onError: error => notice(error.message, true),
    onRenew: beginRenewal,
    onRecover: recoverDevice,
    onRevoke: device => {
      pendingRevoke = device;
      element("confirm-message").textContent = "设备：" + device.name;
      element("confirm-dialog").showModal();
    },
  });
}

async function recoverPackage(id) {
  if (certificateRequest?.deviceId !== id) return;
  const result = await api.request(`/api/devices/${encodeURIComponent(id)}/certificate`);
  if (!result.certificate) return;
  certificateRequest.attachCertificate(result.certificate);
  element("enroll-form").hidden = true;
  element("download-panel").hidden = false;
  element("download-summary").textContent = "证书已签发。请重新打包并保存文件。";
  element("retry-package").hidden = false;
  element("download-p12").disabled = !certificateRequest.readyToDownload;
}

async function recoverDevice(device) {
  setBusy(true, "正在核对");
  try {
    const action = device.status === "issued_pending_allow" ? "retry" : "recover";
    await api.request(`/api/devices/${encodeURIComponent(device.id)}/${action}`, "POST", {});
    await refreshDevices();
    await recoverPackage(device.id);
    notice("证书状态已核对。");
  } finally {
    setBusy(false);
  }
}

function packageCertificate(password) {
  certificateRequest.package(password);
  element("retry-package").hidden = true;
  element("download-p12").disabled = false;
}

async function issueCertificate(event) {
  event.preventDefault();
  if (busy || certificateRequest) return;
  notice("");
  let password = element("import-password").value;
  if (password.length < 16 || password.length > 128 || password !== element("confirm-password").value) {
    notice("导入密码需要 16–128 个字符，且两次输入一致。", true);
    return;
  }

  try {
    setBusy(true, "正在生成密钥");
    certificateRequest = await BrowserCertificate.generate(element("device-name").value.trim());
    element("clear-request").hidden = false;
    const job = await api.request("/api/jobs", "POST", {
      name: certificateRequest.name,
      ...(renewalId ? { replacedId: renewalId } : {}),
    });
    certificateRequest.deviceId = job.deviceId;

    setBusy(true, "正在签发证书");
    const issued = await api.request("/api/issue", "POST", {
      jobId: job.jobId,
      csr: certificateRequest.createCsr(job.cn),
    });
    certificateRequest.attachCertificate(issued.certificate);

    setBusy(true, "正在加密文件");
    await new Promise(resolve => requestAnimationFrame(resolve));
    packageCertificate(password);
    element("enroll-form").hidden = true;
    element("download-panel").hidden = false;
    element("download-summary").textContent = certificateRequest.name + " · 到期 " + formatDate(issued.device.expiresAt);
    notice("证书已签发，请下载并安装。");
    await refreshDevices();
  } catch (error) {
    notice(error.message, true);
    try {
      await refreshDevices();
      if (certificateRequest?.deviceId) await recoverPackage(certificateRequest.deviceId);
    } catch {
      // Preserve the original error and the in-memory key for a later retry.
    }
  } finally {
    password = "";
    element("import-password").value = "";
    element("confirm-password").value = "";
    setBusy(false);
  }
}

function retryPackage() {
  if (!certificateRequest?.hasCertificate) return;
  let password = prompt("设置本次文件的导入密码（16–128 个字符）");
  if (!password) return;
  if (password.length < 16 || password.length > 128) {
    notice("密码长度不符合要求。", true);
    return;
  }
  try {
    packageCertificate(password);
    notice("文件已重新打包，可以下载。");
  } catch {
    notice("打包未完成，请保留页面并核对浏览器。", true);
  } finally {
    password = "";
  }
}

async function revokeCertificate() {
  if (busy) return;
  setBusy(true, "正在撤销");
  element("confirm-revoke").disabled = true;
  try {
    await api.request(`/api/devices/${encodeURIComponent(pendingRevoke.id)}/revoke`, "POST", {});
    notice("证书已撤销。");
  } catch (error) {
    notice(error.message, true);
  } finally {
    element("confirm-dialog").close();
    element("confirm-revoke").disabled = false;
    setBusy(false);
    await refreshDevices().catch(() => {});
  }
}

function bindEvents() {
  element("device-type").addEventListener("change", () => renderInstallGuide(element("device-type").value));
  element("enroll-form").addEventListener("submit", issueCertificate);
  element("generate-password").addEventListener("click", () => {
    if (busy) return;
    const password = randomPassword();
    element("import-password").value = password;
    element("confirm-password").value = password;
    notice("已生成随机密码。请显示并保存，安装时需要输入。");
  });
  element("show-password").addEventListener("click", () => {
    const show = element("import-password").type === "password";
    element("import-password").type = show ? "text" : "password";
    element("show-password").textContent = show ? "隐藏密码" : "显示密码";
  });
  element("download-p12").addEventListener("click", () => certificateRequest?.download());
  element("retry-package").addEventListener("click", retryPackage);
  element("clear-request").addEventListener("click", () => { if (!busy) discardRequest(); });
  element("new-device").addEventListener("click", () => {
    if (confirm("确认已经保存证书文件及导入密码？完成后将清除本机临时密钥。")) {
      resetRequest();
      notice("");
    }
  });
  element("refresh-devices").addEventListener("click", () => refreshDevices().catch(error => notice(error.message, true)));
  element("cancel-revoke").addEventListener("click", () => element("confirm-dialog").close());
  element("confirm-revoke").addEventListener("click", revokeCertificate);
  element("check-connection").addEventListener("click", async () => {
    try {
      await api.request("/api/check", "POST", {});
      notice("连接和防护规则正常。");
    } catch (error) {
      notice(error.message, true);
    }
  });
  element("logout").addEventListener("click", async () => {
    if (certificateRequest || busy) return;
    try {
      await api.request("/api/logout", "POST", {});
      location.assign("/");
    } catch (error) {
      notice(error.message, true);
    }
  });
  window.addEventListener("beforeunload", event => {
    if (certificateRequest || busy) {
      event.preventDefault();
      event.returnValue = "";
    }
  });
}

async function boot() {
  element("device-type").value = deviceType;
  renderInstallGuide(deviceType);
  bindEvents();
  try {
    session = await api.request("/api/session");
    api.setSession(session);
    element("user-name").textContent = session.name;
    element("workspace").hidden = false;
    element("login-panel").hidden = true;
    element("logout").hidden = false;
    element("validity").textContent = "有效期 " + session.validityDays + " 天";
    element("connection-status").textContent = session.configured ? "已配置签发服务。" : "签发服务尚未配置，请联系管理员。";
    setBusy(false);
    await refreshDevices();
  } catch (error) {
    if (error.status !== 401) notice(error.message, true);
  }
}

boot();
