import { encryptField, decryptField, type EncryptionKey } from "@dekimuhq/crypto";
import { generateDek, dekKey } from "./dek";
import { wrapDek, unwrapDek } from "./envelope";

/**
 * Storage port. The consuming app implements this over its real store (Redis,
 * etc.). The keystore package is storage-agnostic; `shred` = `del`.
 *
 * CRITICAL OPERATIONAL INVARIANT (Proof of Forgetting spec §7.3): the backing
 * store for this registry MUST be excluded from long-window backups.
 * Crypto-shred is only as strong as the registry row being the single,
 * non-resurrectable copy of the wrapped DEK.
 */
export interface KeyRegistry {
  get(subjectKeyId: string): string | null;
  put(subjectKeyId: string, wrappedDek: string): void;
  del(subjectKeyId: string): void;
}

/**
 * Per-subject crypto-shred keystore.
 *
 * LIMITATION (in-memory residue): unwrapped DEKs live in Node Buffers/Uint8Arrays
 * that are not explicitly zeroed after use; they persist in the heap until GC and
 * could appear in a core dump or swap. The AUTHORITATIVE copy is the wrapped row in
 * the registry — `shred` destroys that row. Once no other copy of the wrapped
 * DEK survives (backups included), the ciphertext has no key this package can
 * recover. Backups and process-memory residue are the caller's responsibility;
 * they are stated here so the crypto-shred property is not overread.
 */
export class Keystore {
  constructor(
    private readonly registry: KeyRegistry,
    private readonly kek: EncryptionKey,
  ) {}

  /** Provision a DEK for a subject if none exists. Never rotates a live DEK. */
  createSubject(subjectKeyId: string): void {
    if (this.registry.get(subjectKeyId) !== null) return;
    this.registry.put(subjectKeyId, wrapDek(generateDek(), this.kek));
  }

  hasSubject(subjectKeyId: string): boolean {
    return this.registry.get(subjectKeyId) !== null;
  }

  /** Encrypt one field value under the subject's DEK. */
  encrypt(subjectKeyId: string, plain: string): string {
    return encryptField(plain, this.loadDekKey(subjectKeyId));
  }

  /** Decrypt one field value under the subject's DEK. */
  decrypt(subjectKeyId: string, ciphertext: string): string {
    return decryptField(ciphertext, this.loadDekKey(subjectKeyId));
  }

  /** Crypto-shred: destroy the wrapped DEK in this registry. Copies elsewhere (e.g. backups) are the caller's to destroy. */
  shred(subjectKeyId: string): void {
    this.registry.del(subjectKeyId);
  }

  private loadDekKey(subjectKeyId: string): EncryptionKey {
    const wrapped = this.registry.get(subjectKeyId);
    if (!wrapped) throw new Error(`no key for subject ${subjectKeyId} (unknown or shredded)`);
    const dek = unwrapDek(wrapped, this.kek);
    if (!dek) throw new Error(`no key for subject ${subjectKeyId} (wrapped DEK undecryptable)`);
    return dekKey(dek);
  }
}
