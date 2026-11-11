// The only application module that sends HTTP requests.
export class ApiError extends Error {
  constructor(message, status, code) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export class ApiClient {
  #csrf;
  #onUnauthorized;

  constructor(onUnauthorized) {
    this.#onUnauthorized = onUnauthorized;
  }

  setSession(session) {
    this.#csrf = session.csrf;
  }

  async request(path, method = "GET", data) {
    if (!path.startsWith("/api/")) {
      throw new Error("不支持的请求地址。");
    }

    const response = await fetch(path, {
      method,
      credentials: "same-origin",
      cache: "no-store",
      headers: {
        "Content-Type": "application/json",
        ...(this.#csrf ? { "X-CSRF-Token": this.#csrf } : {}),
      },
      body: data === undefined ? undefined : JSON.stringify(data),
    });

    let result;
    try {
      result = await response.json();
    } catch {
      throw new Error("服务器没有返回完整结果，请核对设备列表。");
    }

    if (!response.ok) {
      if (response.status === 401) this.#onUnauthorized();
      throw new ApiError(
        result.error || "操作未完成，请核对设备状态。",
        response.status,
        result.code,
      );
    }
    return result;
  }
}
