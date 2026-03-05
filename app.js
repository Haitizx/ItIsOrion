import * as openpgp from "https://cdn.jsdelivr.net/npm/openpgp@5.11.2/+esm";

/**
 * Chave pública fixa do Órion (pra não depender de MIT / keyserver)
 * cola a mensagem assinada → valida aqui mesmo e acabou
 */
const ORION_PUBLIC_KEY = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: SKS 1.1.6
Comment: Hostname: pgp.mit.edu

mDMEaaE93BYJKwYBBAHaRw8BAQdAb3TkLFB8UvgpzMWNzhncHPb9zRj7uS0sqkVrOLIV75G0
KcOTcmlvbiA8b3Jpb25jb3Jwb3JhdGlvbmJyYXppbEBnbWFpbC5jb20+iLUEExYKAF0WIQS/
hH7Ox4wJQwaqvbG7+onlH/r93QUCaaE93BsUgAAAAAAEAA5tYW51MiwyLjUrMS4xMSwyLDEC
GwMFCQWlX5QFCwkIBwICIgIGFQoJCAsCBBYCAwECHgcCF4AACgkQu/qJ5R/6/d3o4AD+K2j3
yAsk9uhU9GTKpazESzq8+dcjztrsG/Tdc4UsFBkBALXGQ7R/qnarXD3B/XPl+7tvfUJVc2pN
ZdYpR0rwVAoNuDgEaaE93BIKKwYBBAGXVQEFAQEHQIsATlwZXAq2eeCCkFuvgTYeJV6N2OJi
jooNMFLsKBI8AwEIB4iaBBgWCgBCFiEEv4R+zseMCUMGqr2xu/qJ5R/6/d0FAmmhPdwbFIAA
AAAABAAObWFudTIsMi41KzEuMTEsMiwxAhsMBQkFpV+UAAoJELv6ieUf+v3dgP8A/2YNuc/X
6Shl0BBEvj4hf38L/GvC26t4TUafDJqVPNqRAQDBX9yhgE5xH60NncgS1XA0weoI8Yrvv2SE
RRgsy9KCAQ==
=289i
-----END PGP PUBLIC KEY BLOCK-----`;

/**
 * Fingerprint pra garantir que a key que tá embutida é a certa.
 * (anti "trocaram a chave" / anti cagada)
 */
const ORION_FINGERPRINT = "BF847ECEC78C094306AABDB1BBFA89E51FFAFDDD";

const $ = (id) => document.getElementById(id);

const els = {
  blob: $("blob"),
  verify: $("verify"),
  status: $("status"),
  meta: $("meta"),
};

function setStatus(kind, text, meta = "") {
  els.status.textContent = text;
  els.meta.textContent = meta;

  els.status.style.color =
    kind === "ok" ? "var(--ok)" :
    kind === "bad" ? "var(--bad)" :
    kind === "warn" ? "var(--warn)" :
    "var(--text)";
}

function summarizeKey(publicKey) {
  const userIDs = publicKey.getUserIDs ? publicKey.getUserIDs() : [];
  const fp = publicKey.getFingerprint ? publicKey.getFingerprint() : "";
  const alg = publicKey.getAlgorithmInfo ? publicKey.getAlgorithmInfo() : null;

  return {
    fingerprint: fp,
    userIDs,
    algorithm: alg ? `${alg.algorithm} (${alg.bits} bits)` : "—",
  };
}

function formatMeta({ publicKey, signature }) {
  const k = summarizeKey(publicKey);

  let keyID = "—";
  if (signature?.keyID) {
    try {
      keyID = signature.keyID.toHex ? signature.keyID.toHex() : String(signature.keyID);
    } catch {
      keyID = String(signature.keyID);
    }
  }

  const created =
    signature?.signature?.created
      ? new Date(signature.signature.created).toISOString()
      : "—";

  return [
    `Fingerprint: ${k.fingerprint || "—"}`,
    `User IDs: ${k.userIDs?.length ? k.userIDs.join(" | ") : "—"}`,
    `Algoritmo: ${k.algorithm}`,
    `KeyID (assinatura): ${keyID}`,
    `Assinatura criada: ${created}`,
  ].join("\n");
}

async function loadOrionKey() {
  const publicKey = await openpgp.readKey({ armoredKey: ORION_PUBLIC_KEY });

  // conferindo fingerprint, só pra garantir
  const fp = (publicKey.getFingerprint?.() || "").toUpperCase();
  if (fp && fp !== ORION_FINGERPRINT) {
    throw new Error(
      `Fingerprint da chave embutida não bate.\nEsperado: ${ORION_FINGERPRINT}\nEncontrado: ${fp}`
    );
  }
  return publicKey;
}

async function verifyOrionCleartext(signedMessageArmored) {
  const publicKey = await loadOrionKey();
  const message = await openpgp.readCleartextMessage({ cleartextMessage: signedMessageArmored });

  const result = await openpgp.verify({
    message,
    verificationKeys: publicKey,
  });

  // pode ter mais de 1 assinatura, aqui valida a primeira que passar
  for (const sig of result.signatures) {
    try {
      await sig.verified;
      return { publicKey, signature: sig };
    } catch {
      // tenta a próxima
    }
  }

  throw new Error("Nenhuma assinatura válida encontrada.");
}

els.verify.addEventListener("click", async () => {
  const blob = els.blob.value;

  if (!blob.trim()) {
    setStatus("warn", "Cole a mensagem assinada do Órion aí.", "");
    return;
  }

  // aqui é o ponto: não tem pubkey input. só precisa do SIGNED MESSAGE.
  if (!blob.includes("-----BEGIN PGP SIGNED MESSAGE-----")) {
    setStatus("warn", "Isso não parece uma mensagem cleartext assinada (BEGIN PGP SIGNED MESSAGE).", "");
    return;
  }

  try {
    setStatus("neutral", "Verificando…", "");

    const start = blob.indexOf("-----BEGIN PGP SIGNED MESSAGE-----");
    const signedArmored = blob.slice(start).trim();

    const out = await verifyOrionCleartext(signedArmored);

    setStatus("ok", "✅ Assinatura VÁLIDA (Órion)", formatMeta(out));
  } catch (e) {
    setStatus("bad", "❌ Assinatura INVÁLIDA (ou mensagem alterada)", String(e));
  }
});