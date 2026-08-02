import { describe, it, expect } from 'vitest';
import { classifyUserAgent } from 'forest-shared-resources/user-agents';
import vectors from 'forest-shared-resources/contracts/user-agents.vectors.json';
import { TARBALL_PATH } from '../src/index';

/*
    The classification vectors are the shared cross-repo contract
    (forest-backend and forest-cli assert the same file) — same lockstep
    mechanism as the deriveObjectEncryptionKey vector.
*/
describe('classifyUserAgent', () => {
	it('matches the shared contract vectors', () => {
		for (const [ua, expected] of vectors.classifications as [string | null, string][]) {
			expect(classifyUserAgent(ua), JSON.stringify(ua)).toBe(expected);
		}
	});
});

describe('TARBALL_PATH', () => {
	const HASH = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

	it('extracts access and hash from public paths', () => {
		const m = TARBALL_PATH.exec(`/public/${HASH}.tgz`);
		expect(m?.[1]).toBe('public');
		expect(m?.[2]).toBe(HASH);
	});

	it('extracts access and hash from private paths', () => {
		const m = TARBALL_PATH.exec(`/private/${HASH}.tgz`);
		expect(m?.[1]).toBe('private');
		expect(m?.[2]).toBe(HASH);
	});

	it('rejects uppercase hex', () => {
		expect(TARBALL_PATH.test(`/public/${HASH.toUpperCase()}.tgz`)).toBe(false);
	});

	it('rejects wrong-length hashes', () => {
		expect(TARBALL_PATH.test(`/public/${HASH.slice(0, 63)}.tgz`)).toBe(false);
		expect(TARBALL_PATH.test(`/public/${HASH}0.tgz`)).toBe(false);
	});

	it('rejects non-tgz and nested paths', () => {
		expect(TARBALL_PATH.test(`/public/${HASH}.zip`)).toBe(false);
		expect(TARBALL_PATH.test(`/public/extra/${HASH}.tgz`)).toBe(false);
		expect(TARBALL_PATH.test(`/other/${HASH}.tgz`)).toBe(false);
	});
});
