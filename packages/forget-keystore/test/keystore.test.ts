import { describe, it, expect } from "vitest";
import { loadKey } from "@dekimuhq/crypto";
import { Keystore, type KeyRegistry } from "../src/keystore";

/** In-memory registry port for tests. */
function memRegistry(): KeyRegistry {
  const m = new Map<string, string>();
  return {
    get: (id) => m.get(id) ?? null,
    put: (id, wrapped) => void m.set(id, wrapped),
    del: (id) => void m.delete(id),
  };
}

const kek = loadKey(Buffer.alloc(32, 3).toString("base64"));

describe("Keystore", () => {
  it("encrypts and decrypts a subject's field through a per-subject DEK", () => {
    const ks = new Keystore(memRegistry(), kek);
    ks.createSubject("subject-A");
    const ct = ks.encrypt("subject-A", "jane@example.com");
    expect(ct.startsWith("enc:v1:")).toBe(true);
    expect(ks.decrypt("subject-A", ct)).toBe("jane@example.com");
  });

  it("after shred, the keystore can no longer decrypt the subject's ciphertext", () => {
    const ks = new Keystore(memRegistry(), kek);
    ks.createSubject("subject-A");
    const ct = ks.encrypt("subject-A", "jane@example.com");

    ks.shred("subject-A");

    expect(() => ks.decrypt("subject-A", ct)).toThrow(/no key|shredded/i);
    expect(ks.hasSubject("subject-A")).toBe(false);
  });

  it("createSubject is idempotent-safe: does not overwrite an existing live DEK", () => {
    const reg = memRegistry();
    const ks = new Keystore(reg, kek);
    ks.createSubject("subject-A");
    const ct = ks.encrypt("subject-A", "secret");
    ks.createSubject("subject-A"); // must NOT rotate the DEK out from under existing ciphertext
    expect(ks.decrypt("subject-A", ct)).toBe("secret");
  });

  it("does not overwrite a live DEK even if the registry row is an empty string", () => {
    // A real backend can return "" (a valid `string` per the port type). createSubject
    // must treat "" as 'subject exists', never as 'missing' — else it silently rotates
    // out a live DEK. We assert createSubject is a no-op when a row (even "") is present.
    const m = new Map<string, string>();
    let putCount = 0;
    const reg: KeyRegistry = {
      get: (id) => (m.has(id) ? (m.get(id) as string) : null),
      put: (id, w) => { putCount++; m.set(id, w); },
      del: (id) => void m.delete(id),
    };
    const ks = new Keystore(reg, kek);
    m.set("subject-A", ""); // simulate an existing empty row
    ks.createSubject("subject-A");
    expect(putCount).toBe(0); // must NOT have written a new DEK
    expect(ks.hasSubject("subject-A")).toBe(true);
  });

  it("encrypt throws for an unknown / shredded subject", () => {
    const ks = new Keystore(memRegistry(), kek);
    expect(() => ks.encrypt("ghost", "x")).toThrow(/no key|shredded|unknown/i);
  });
});
