import { IV_BYTES, RSA_ALGORITHM, VAULT_VERSION_V2 } from "./types.js";
import type {
  BlobClass,
  BlobContext,
  BlobPurpose,
  DataKey,
  EncryptedContent,
  EncryptedContentV2,
  ExpectedBlobContext,
} from "./types.js";
import { toBase64Url, fromBase64Url, toBuffer } from "./encoding.js";
import { computeKidForKey, derivePublicKeyFromPrivate } from "./keypair.js";
import { decryptContent } from "./content.js";

const crypto = globalThis.crypto;

const PURPOSES: readonly BlobPurpose[] = ["field", "file", "backup", "share"];

/** HKDF `info` labels. Changing either one changes every derived key. */
export const WDK_INFO_PREFIX = "dekimu/wdk/v1|";
export const PDK_INFO = "dekimu/pdk/v1";

/** Thrown when a blob's header does not match what the reader asked for. */
export class BlobContextError extends Error {
  constructor(
    readonly field: string,
    message = `blob context mismatch: ${field}`,
  ) {
    super(message);
    this.name = "BlobContextError";
  }
}

// ── Derived data keys ─────────────────────────────────────────────

async function hkdfAesKey(
  ikm: Uint8Array,
  salt: string,
  info: string,
): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey(
    "raw",
    toBuffer(ikm),
    "HKDF",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: toBuffer(enc.encode(salt)),
      info: toBuffer(enc.encode(info)),
    },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function requireId(name: string, value: string): void {
  if (typeof value !== "string" || value === "" || !isWellFormed(value)) {
    throw new Error(`${name} must be a non-empty, well-formed string`);
  }
}

/**
 * Derive the data key for a workspace scope:
 * HKDF-SHA256(ikm = JWK `d` of the workspace private key, salt = wsId,
 * info = "dekimu/wdk/v1|" + kid).
 *
 * `privateKey` is either an extractable RSA private key or the base64url PKCS8
 * a member holds right after unwrapping their grant. importPrivateKeyPkcs8
 * returns a non-extractable handle, so derive from the PKCS8 at that moment;
 * it is imported here only transiently. The kid is checked against the key so
 * a wrong pairing fails here rather than producing blobs nobody can open.
 */
export async function deriveWorkspaceDataKey(
  privateKey: CryptoKey | string,
  wsId: string,
  kid: string,
): Promise<DataKey> {
  requireId("wsId", wsId);
  requireId("kid", kid);
  const key =
    typeof privateKey === "string"
      ? await crypto.subtle.importKey(
          "pkcs8",
          toBuffer(fromBase64Url(privateKey)),
          RSA_ALGORITHM,
          true,
          ["decrypt"],
        )
      : privateKey;
  if (!key.extractable) {
    throw new Error(
      "workspace private key is not extractable; pass its PKCS8 instead",
    );
  }
  const jwk = await crypto.subtle.exportKey("jwk", key);
  if (jwk.kty !== "RSA" || !jwk.d) {
    throw new Error("workspace private key is not an RSA private key");
  }
  const actualKid = await computeKidForKey(await derivePublicKeyFromPrivate(key));
  if (actualKid !== kid) {
    throw new Error("kid does not match the workspace private key");
  }
  return {
    scope: `ws:${wsId}`,
    kid,
    key: await hkdfAesKey(fromBase64Url(jwk.d), wsId, WDK_INFO_PREFIX + kid),
  };
}

/**
 * Derive the data key for a personal scope:
 * HKDF-SHA256(ikm = raw vault key, salt = userId, info = "dekimu/pdk/v1").
 * The vault key must be extractable (decryptVaultKey and recovery import it so).
 */
export async function derivePersonalDataKey(
  vaultKey: CryptoKey,
  userId: string,
): Promise<DataKey> {
  requireId("userId", userId);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", vaultKey));
  return {
    scope: `u:${userId}`,
    key: await hkdfAesKey(raw, userId, PDK_INFO),
  };
}

// ── AAD ───────────────────────────────────────────────────────────

// Lone surrogates are not valid I-JSON and TextEncoder would map them to
// U+FFFD, so two different strings could share one AAD. Refuse them.
function isWellFormed(s: string): boolean {
  return !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(s);
}

function checkContext(ctx: BlobContext): void {
  if (typeof ctx.scope !== "string" || !/^(ws|u):./s.test(ctx.scope)) {
    throw new BlobContextError("scope", "scope must be ws:<id> or u:<id>");
  }
  for (const f of ["scope", "kid", "coll", "rec", "field"] as const) {
    if (typeof ctx[f] !== "string" || !isWellFormed(ctx[f])) {
      throw new BlobContextError(f, `${f} must be a well-formed string`);
    }
  }
  if (ctx.kid === "") throw new BlobContextError("kid", "kid must be non-empty");
  for (const f of ["epoch", "ver"] as const) {
    if (!Number.isSafeInteger(ctx[f]) || ctx[f] < 0) {
      throw new BlobContextError(f, `${f} must be a non-negative safe integer`);
    }
  }
  if (!PURPOSES.includes(ctx.purpose)) {
    throw new BlobContextError("purpose", "unknown purpose");
  }
}

/**
 * AAD = UTF-8(JCS({v, cls, scope, kid, epoch, purpose, coll, rec, field, ver})).
 *
 * The object is flat and holds only strings and non-negative safe integers, so
 * RFC 8785 reduces to: keys sorted by UTF-16 code units, JSON.stringify for
 * each string and integer, no whitespace. Exported for test vectors only.
 */
export function blobAad(cls: BlobClass, ctx: BlobContext): Uint8Array {
  checkContext(ctx);
  const obj: Record<string, string | number> = {
    v: VAULT_VERSION_V2,
    cls,
    scope: ctx.scope,
    kid: ctx.kid,
    epoch: ctx.epoch,
    purpose: ctx.purpose,
    coll: ctx.coll,
    rec: ctx.rec,
    field: ctx.field,
    ver: ctx.ver,
  };
  const body = Object.keys(obj)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${JSON.stringify(obj[k])}`)
    .join(",");
  return new TextEncoder().encode(`{${body}}`);
}

function pickContext(ctx: BlobContext): BlobContext {
  const { scope, kid, epoch, purpose, coll, rec, field, ver } = ctx;
  return { scope, kid, epoch, purpose, coll, rec, field, ver };
}

// ── Encrypt ───────────────────────────────────────────────────────

function isDataKey(k: DataKey | CryptoKey): k is DataKey {
  return typeof (k as DataKey).scope === "string" && "key" in k;
}

/**
 * Encrypt into a `zkv2` envelope bound to `meta`.
 *
 * - A DataKey (from deriveWorkspaceDataKey / derivePersonalDataKey) writes
 *   `cls:"member"`: AES-256-GCM under the derived key. Only holders of the
 *   underlying secret can produce such a blob.
 * - An RSA public key writes `cls:"inbound"`: the hybrid format with AAD, for
 *   writers that hold only the public key. Confidential, not authenticated, and
 *   only allowed at `ver: 0`.
 */
export async function encryptBlob(
  plaintext: string,
  keyMaterial: DataKey | CryptoKey,
  meta: BlobContext,
): Promise<EncryptedContentV2> {
  const ctx = pickContext(meta);
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const pt = new TextEncoder().encode(plaintext);

  if (isDataKey(keyMaterial)) {
    if (keyMaterial.scope !== ctx.scope) throw new BlobContextError("scope");
    if (keyMaterial.kid !== undefined && keyMaterial.kid !== ctx.kid) {
      throw new BlobContextError("kid");
    }
    const aad = blobAad("member", ctx);
    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: toBuffer(iv), additionalData: toBuffer(aad) },
      keyMaterial.key,
      toBuffer(pt),
    );
    return {
      v: VAULT_VERSION_V2,
      cls: "member",
      ...ctx,
      iv: toBase64Url(iv),
      data: toBase64Url(new Uint8Array(ct)),
    };
  }

  if (ctx.ver !== 0) {
    throw new BlobContextError("ver", "inbound blobs are only allowed at ver 0");
  }
  if ((await computeKidForKey(keyMaterial)) !== ctx.kid) {
    throw new BlobContextError("kid", "kid does not match recipientPublicKey");
  }
  const aad = blobAad("inbound", ctx);
  const contentKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt"],
  );
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: toBuffer(iv), additionalData: toBuffer(aad) },
    contentKey,
    toBuffer(pt),
  );
  const wrapped = await crypto.subtle.wrapKey("raw", contentKey, keyMaterial, {
    name: "RSA-OAEP",
  });
  return {
    v: VAULT_VERSION_V2,
    cls: "inbound",
    ...ctx,
    iv: toBase64Url(iv),
    data: toBase64Url(new Uint8Array(ct)),
    key: toBase64Url(new Uint8Array(wrapped)),
  };
}

// ── Decrypt ───────────────────────────────────────────────────────

export interface BlobKeys {
  /** Required to open `cls:"member"` blobs. */
  dataKey?: DataKey;
  /** RSA private key; required to open `cls:"inbound"` and `zkv1` blobs. */
  privateKey?: CryptoKey;
}

export interface DecryptedBlob {
  plaintext: string;
  /** `legacy` = a zkv1 blob; re-seal it as zkv2 when the record is next written. */
  cls: BlobClass | "legacy";
}

/**
 * Decrypt a `zkv2` (or, unless `expected.rejectV1`, a `zkv1`) blob.
 *
 * The AAD is built from `expected`, never from the blob. The blob's own header
 * is compared to `expected` first only to fail with a clear error; even
 * without that check a mismatched header could not pass the GCM tag.
 *
 * `inbound` blobs are accepted only when `expected.ver` is 0, so a writer that
 * holds just the public key cannot replace a later member version. The caller
 * should treat `cls:"inbound"` content as unauthenticated.
 */
export async function decryptBlob(
  enc: EncryptedContentV2 | EncryptedContent,
  keys: BlobKeys,
  expected: ExpectedBlobContext,
): Promise<DecryptedBlob> {
  const ctx = pickContext(expected);
  checkContext(ctx);

  if (enc.v !== VAULT_VERSION_V2) {
    if (enc.v !== "zkv1") throw new BlobContextError("v", "unknown version");
    if (expected.rejectV1) {
      throw new BlobContextError("v", "zkv1 blob refused in a migrated scope");
    }
    if (!keys.privateKey) throw new Error("privateKey required for zkv1");
    return {
      plaintext: await decryptContent(enc, keys.privateKey),
      cls: "legacy",
    };
  }

  const cls = enc.cls;
  if (cls !== "member" && cls !== "inbound") {
    throw new BlobContextError("cls", "unknown cls");
  }
  for (const f of Object.keys(ctx) as (keyof BlobContext)[]) {
    if (enc[f] !== ctx[f]) throw new BlobContextError(f);
  }
  const aad = toBuffer(blobAad(cls, ctx));
  const iv = fromBase64Url(enc.iv);
  if (iv.length !== IV_BYTES) throw new BlobContextError("iv", "bad iv length");
  const data = toBuffer(fromBase64Url(enc.data));

  let contentKey: CryptoKey;
  if (cls === "member") {
    if (enc.key !== undefined) {
      throw new BlobContextError("key", "member blob must not carry a key");
    }
    const dk = keys.dataKey;
    if (!dk) throw new Error("dataKey required for member blobs");
    if (dk.scope !== ctx.scope) throw new BlobContextError("scope");
    if (dk.kid !== undefined && dk.kid !== ctx.kid) {
      throw new BlobContextError("kid");
    }
    contentKey = dk.key;
  } else {
    if (ctx.ver !== 0) {
      throw new BlobContextError("ver", "inbound blobs are only accepted at ver 0");
    }
    if (typeof enc.key !== "string") {
      throw new BlobContextError("key", "inbound blob is missing its key");
    }
    if (!keys.privateKey) throw new Error("privateKey required for inbound blobs");
    contentKey = await crypto.subtle.unwrapKey(
      "raw",
      toBuffer(fromBase64Url(enc.key)),
      keys.privateKey,
      { name: "RSA-OAEP" },
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
  }

  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: toBuffer(iv), additionalData: aad },
    contentKey,
    data,
  );
  return { plaintext: new TextDecoder().decode(pt), cls };
}
