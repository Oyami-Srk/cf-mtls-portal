const statusLabels = {
  active: "可用",
  revoked: "已撤销",
  pending_revocation: "正在撤销",
  pending_reactivation: "正在启用",
  unverified: "状态待核对",
  issuing: "正在签发",
  issue_uncertain: "需核对签发结果",
  issued_pending_allow: "等待开通",
  revocation_pending: "撤销未完成",
  blocked_pending_revoke: "已禁止访问，待撤销",
  manual_review: "需人工核对",
  failed: "未签发",
};

export function formatDate(value) {
  return value ? new Date(value).toLocaleDateString("zh-CN") : "—";
}

function action(label, handler, callbacks) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "button is-small is-text mb-0";
  button.textContent = label;
  button.addEventListener("click", () => {
    if (callbacks.isBusy()) return;
    Promise.resolve(handler()).catch(callbacks.onError);
  });
  return button;
}

function deviceRow(device, callbacks) {
  const row = document.createElement("tr");
  const name = document.createElement("td");
  const title = document.createElement("div");
  title.textContent = device.name;
  const fingerprint = document.createElement("small");
  fingerprint.className = "is-family-code has-text-grey";
  fingerprint.textContent = device.fingerprint ? device.fingerprint.slice(0, 12) + "…" : "";
  fingerprint.title = device.fingerprint || "";
  name.append(title, fingerprint);

  const status = document.createElement("td");
  status.textContent = statusLabels[device.status] || "状态待核对";
  if (device.status !== "active") status.className = "has-text-danger";
  const expiry = document.createElement("td");
  expiry.textContent = formatDate(device.expiresAt);

  const actions = document.createElement("td");
  const group = document.createElement("div");
  group.className = "device-actions buttons is-right mb-0";
  if (device.managed && device.status === "active") {
    group.append(action("续签", () => callbacks.onRenew(device), callbacks));
  }
  if (device.managed && ["issued_pending_allow", "issue_uncertain", "issuing"].includes(device.status)) {
    const label = device.status === "issued_pending_allow" ? "重试开通" : "核对结果";
    group.append(action(label, () => callbacks.onRecover(device), callbacks));
  }
  if (device.managed && ["active", "issued_pending_allow", "revocation_pending", "blocked_pending_revoke"].includes(device.status)) {
    group.append(action("撤销", () => callbacks.onRevoke(device), callbacks));
  }
  if (!device.managed) {
    const label = document.createElement("small");
    label.className = "has-text-grey";
    label.textContent = "既有证书";
    group.append(label);
  }
  actions.append(group);
  row.append(name, status, expiry, actions);
  return row;
}

// Presentation only: callbacks own all actions; untrusted fields use textContent.
export function renderDevices(result, callbacks) {
  const devices = [...result.pinned, ...result.devices.map(device => ({ ...device, managed: true }))];
  document.getElementById("device-list").replaceChildren(
    ...devices.map(device => deviceRow(device, callbacks)),
  );
  document.getElementById("empty-list").hidden = devices.length > 0;
}
