import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { generateKeyPairSync, randomBytes, webcrypto } from "node:crypto";
import test from "node:test";
import { BrowserCertificate } from "../assets/js/certificates.mjs";
import { ApiClient } from "../assets/js/api.mjs";

// Test-only browser shims. No real accounts, credentials, or network endpoints.
const require = createRequire(import.meta.url);
globalThis.window = globalThis;
globalThis.forge = require("../assets/vendor/forge.min.js");
// The browser bundle omits Node's crypto adapter; bridge its entropy hook to
// the real Node CSPRNG rather than substituting any signing/encryption logic.
globalThis.forge.random.seedFileSync = size => randomBytes(size).toString("binary");
Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
Object.defineProperty(globalThis, "isSecureContext", { value: true, configurable: true });

function certificateFor(csrPem, overridePublicKey) {
  const csr = forge.pki.certificationRequestFromPem(csrPem);
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const signingKey = forge.pki.privateKeyFromPem(privateKey.export({ type: "pkcs8", format: "pem" }));
  const certificate = forge.pki.createCertificate();
  certificate.publicKey = overridePublicKey || csr.publicKey;
  certificate.serialNumber = "01";
  certificate.validity.notBefore = new Date();
  certificate.validity.notAfter = new Date(Date.now() + 86400_000);
  certificate.setSubject(csr.subject.attributes);
  certificate.setIssuer([{ name: "commonName", value: "Unit test issuer" }]);
  certificate.sign(signingKey, forge.md.sha256.create());
  return forge.pki.certificateToPem(certificate);
}

test("browser key produces a signed CSR and a password-protected matching PKCS#12", async () => {
  const request = await BrowserCertificate.generate("Unit test device");
  const csrPem = request.createCsr("mtls-device-unit-test");
  const csr = forge.pki.certificationRequestFromPem(csrPem);
  assert.equal(csr.verify(), true);
  assert.equal(csr.subject.getField("CN").value, "mtls-device-unit-test");
  assert.equal(csr.publicKey.n.bitLength(), 2048);
  assert.equal(csr.publicKey.e.intValue(), 65537);
  assert.equal(csrPem.includes("PRIVATE KEY"), false);
  assert.equal(JSON.stringify(request).includes("PRIVATE KEY"), false);

  request.attachCertificate(certificateFor(csrPem));
  request.package("unit-test-password-not-a-real-credential");
  assert.equal(request.readyToDownload, true);

  let downloadedUrl;
  globalThis.document = {
    body: { append() {} },
    createElement() { return { click() { downloadedUrl = this.href; }, remove() {} }; },
  };
  request.download();
  const bytes = new Uint8Array(await (await fetch(downloadedUrl)).arrayBuffer());
  const der = String.fromCharCode(...bytes);
  const p12 = forge.pkcs12.pkcs12FromAsn1(
    forge.asn1.fromDer(der), "unit-test-password-not-a-real-credential",
  );
  const bags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
  assert.equal(bags[forge.pki.oids.pkcs8ShroudedKeyBag][0].key.n.toString(16), csr.publicKey.n.toString(16));
  assert.throws(() => forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(der), "wrong password"));
  request.dispose();
  assert.equal(request.readyToDownload, false);
  await assert.rejects(fetch(downloadedUrl));
});

test("a certificate for another public key cannot be attached", async () => {
  const request = await BrowserCertificate.generate("Unit test mismatch");
  const other = await BrowserCertificate.generate("Other unit test device");
  const csr = request.createCsr("mtls-device-first");
  const otherKey = forge.pki.certificationRequestFromPem(other.createCsr("mtls-device-other")).publicKey;
  assert.throws(() => request.attachCertificate(certificateFor(csr, otherKey)), /公钥不匹配/);
  assert.equal(request.hasCertificate, false);
  request.dispose();
  other.dispose();
});

test("API client refuses external destinations before sending any request", async () => {
  const api = new ApiClient(() => {});
  await assert.rejects(api.request("https://example.invalid/steal", "POST", { csrf: "test" }));
  await assert.rejects(api.request("//example.invalid/steal"));
});
