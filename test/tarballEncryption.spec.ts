import { describe, it, expect } from 'vitest';
import { deriveObjectEncryptionKey, base64ToBytes } from '../src/index';

/*
    THE SHARED TEST VECTOR. forest-trust-gateway implements the same
    derivation against node:crypto and asserts this exact vector
    (tests/rules/tarballEncryption.test.ts there) — the two services only
    interoperate if both tests pass against these same constants. Change
    one side and the other MUST change with it.
*/
const VECTOR = {
	masterB64: 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=', // utf8 "0123456789abcdef0123456789abcdef"
	storageKey: 'private/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.tgz',
	derivedHex: 'a44177118f91c80a726a2be68bafe1d782c2093952661157e24976dc9a0547e1',
};

function toHex(buf: ArrayBuffer): string {
	return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

describe('deriveObjectEncryptionKey', () => {
	it('derives the shared cross-service test vector exactly', async () => {
		const derived = await deriveObjectEncryptionKey(VECTOR.masterB64, VECTOR.storageKey);
		expect(toHex(derived)).toBe(VECTOR.derivedHex);
	});

	it('produces 32-byte keys — the length SSE-C requires', async () => {
		const derived = await deriveObjectEncryptionKey(VECTOR.masterB64, VECTOR.storageKey);
		expect(derived.byteLength).toBe(32);
	});

	it('derives unrelated keys for different object keys', async () => {
		const other = await deriveObjectEncryptionKey(
			VECTOR.masterB64,
			'private/0000000000000000000000000000000000000000000000000000000000000000.tgz'
		);
		expect(toHex(other)).not.toBe(VECTOR.derivedHex);
	});

	it('rejects master keys that are not exactly 32 bytes', async () => {
		const short = btoa('too-short');
		await expect(deriveObjectEncryptionKey(short, VECTOR.storageKey)).rejects.toThrow(/32 bytes/);
	});
});

describe('base64ToBytes', () => {
	it('round-trips the vector master key', () => {
		const bytes = base64ToBytes(VECTOR.masterB64);
		expect(new TextDecoder().decode(bytes)).toBe('0123456789abcdef0123456789abcdef');
	});
});
