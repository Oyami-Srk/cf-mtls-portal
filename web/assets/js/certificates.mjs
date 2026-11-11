// Cryptographic boundary: this module never sends network requests or stores data.
// Private fields keep key material out of the page controller and JSON payloads.
function forgeApi() {
  if (!globalThis.forge) throw new Error("证书组件尚未加载，请稍后重试。");
  return globalThis.forge;
}

function binary(bytes) {
  let output = "";
  for (let offset = 0; offset < bytes.length; offset += 8192) {
    output += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
  }
  return output;
}

export function randomPassword() {
  return btoa(binary(crypto.getRandomValues(new Uint8Array(18))))
    .replaceAll("+", "-")
    .replaceAll("/", "_");
}

export class BrowserCertificate {
  #privateKey;
  #publicKey;
  #certificate;
  #packageUrl;

  constructor(name, privateKey, publicKey) {
    this.name = name;
    this.#privateKey = privateKey;
    this.#publicKey = publicKey;
  }

  static async generate(name) {
    if (!globalThis.isSecureContext || !crypto.subtle) {
      throw new Error("请使用支持 WebCrypto 的浏览器，通过 HTTPS 打开页面。");
    }
    const forge = forgeApi();
    const key = await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"],
    );
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", key.privateKey));
    const spki = new Uint8Array(await crypto.subtle.exportKey("spki", key.publicKey));
    try {
      return new BrowserCertificate(
        name,
        forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(binary(pkcs8))),
        forge.pki.publicKeyFromAsn1(forge.asn1.fromDer(binary(spki))),
      );
    } finally {
      pkcs8.fill(0);
    }
  }

  createCsr(commonName) {
    const forge = forgeApi();
    const csr = forge.pki.createCertificationRequest();
    csr.publicKey = this.#publicKey;
    csr.setSubject([{ name: "commonName", value: commonName }]);
    csr.sign(this.#privateKey, forge.md.sha256.create());
    return forge.pki.certificationRequestToPem(csr);
  }

  attachCertificate(certificate) {
    const cert = forgeApi().pki.certificateFromPem(certificate);
    if (
      cert.publicKey.n.toString(16) !== this.#publicKey.n.toString(16) ||
      cert.publicKey.e.toString(16) !== this.#publicKey.e.toString(16)
    ) {
      throw new Error("证书公钥不匹配，未打包私钥。");
    }
    this.#certificate = certificate;
  }

  get hasCertificate() {
    return Boolean(this.#certificate);
  }

  get readyToDownload() {
    return Boolean(this.#packageUrl);
  }

  package(password) {
    const forge = forgeApi();
    const cert = forge.pki.certificateFromPem(this.#certificate);
    const p12 = forge.pkcs12.toPkcs12Asn1(this.#privateKey, [cert], password, {
      algorithm: "aes256",
      count: 100000,
      saltSize: 16,
      useMac: true,
      friendlyName: "mTLS · " + this.name,
      generateLocalKeyId: true,
    });
    const output = Uint8Array.from(forge.asn1.toDer(p12).getBytes(), c => c.charCodeAt(0));
    if (this.#packageUrl) URL.revokeObjectURL(this.#packageUrl);
    this.#packageUrl = URL.createObjectURL(
      new Blob([output], { type: "application/x-pkcs12" }),
    );
    output.fill(0);
  }

  download() {
    if (!this.#packageUrl) return;
    const link = document.createElement("a");
    link.href = this.#packageUrl;
    link.download = "mtls-" + this.name.replace(/[^\p{L}\p{N}_-]/gu, "_") + ".p12";
    document.body.append(link);
    link.click();
    link.remove();
  }

  dispose() {
    if (this.#packageUrl) URL.revokeObjectURL(this.#packageUrl);
    this.#packageUrl = undefined;
    this.#privateKey = undefined;
    this.#publicKey = undefined;
    this.#certificate = undefined;
  }
}
