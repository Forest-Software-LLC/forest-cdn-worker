/**
 * forest-cdn-worker
 *
 * Gates the package-tarball CDN. Public paths pass straight through to the
 * R2 custom domain. `/private/` paths require an unexpired HMAC-signed URL
 * (signed by forest-trust-gateway with the shared WORKER_SIG_KEY), and are
 * then served out of R2 via the bucket binding using SSE-C: private objects
 * are encrypted at rest under per-object keys derived from TARBALL_ENC_KEY
 * (shared with the gateway, which encrypts on publish), so no path that
 * skips this worker (public bucket URL, leaked storage credentials, a
 * lockfile-leaked object hash) can produce plaintext.
 */

export default {
	async fetch(request, env, ctx): Promise<Response> {
		const url = new URL(request.url);

    // Only protect the `/private/` path
    if (!url.pathname.startsWith('/private/')) {
      return fetch(request); // Let public files go through
    }

    const expires = url.searchParams.get('expires');
    const signature = url.searchParams.get('signature');

    if (!expires || !signature) {
      return new Response('Missing signature or expiration', { status: 403 });
    }

    // Check if link expired
    const now = Math.floor(Date.now() / 1000);
    if (parseInt(expires) < now) {
      return new Response('Link expired', { status: 403 });
    }

    // Recreate the string used to generate the signature
    const unsignedUrl = `${url.pathname}?expires=${expires}`;

    // Validate the signature
    const valid = await isSignatureValid(unsignedUrl, signature, env.WORKER_SIG_KEY);
    if (!valid) {
      return new Response('Invalid signature', { status: 403 });
    }

    return servePrivateObject(request, env.PACKAGES_BUCKET, env.TARBALL_ENC_KEY, url.pathname);
  },
} satisfies ExportedHandler<Env>;

async function servePrivateObject(request: Request, bucket: R2Bucket, masterKeyB64: string, pathname: string): Promise<Response> {
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return new Response('Method not allowed', { status: 405 });
  }

  // "/private/<sha256>.tgz" → object key "private/<sha256>.tgz"
  const objectKey = pathname.slice(1);
  const ssecKey = await deriveObjectEncryptionKey(masterKeyB64, objectKey);

  const object = await bucket.get(objectKey, { ssecKey });
  if (!object) {
    return new Response('Not found', { status: 404 });
  }

  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set('etag', object.httpEtag);
  if (!headers.has('content-type')) {
    headers.set('content-type', 'application/gzip');
  }
  headers.set('content-length', String(object.size));
  // Signed URLs are short-lived and per-viewer; never let a shared cache
  // hold the decrypted bytes.
  headers.set('cache-control', 'private, no-store');

  return new Response(request.method === 'HEAD' ? null : object.body, { headers });
}

/*
    Per-object SSE-C key: HMAC-SHA256(masterKey, objectKey). Mirrors
    forest-trust-gateway's src/rules/tarballEncryption.ts exactly — the
    shared test vector in test/tarballEncryption.spec.ts (and its twin in
    the gateway's tests) keeps the two implementations in lockstep.
*/
export async function deriveObjectEncryptionKey(masterKeyB64: string, objectKey: string): Promise<ArrayBuffer> {
  const masterKey = base64ToBytes(masterKeyB64);
  if (masterKey.length !== 32) {
    throw new Error('TARBALL_ENC_KEY must be base64 of exactly 32 bytes');
  }
  const key = await crypto.subtle.importKey(
    'raw',
    masterKey,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return crypto.subtle.sign('HMAC', key, new TextEncoder().encode(objectKey));
}

export function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function isSignatureValid(data : string, signature : string, secret : string) {
	const encoder = new TextEncoder();
	const key = await crypto.subtle.importKey(
	  'raw',
	  encoder.encode(secret),
	  { name: 'HMAC', hash: 'SHA-256' },
	  false,
	  ['verify']
	);

	const sig = hexToBytes(signature);
	return crypto.subtle.verify('HMAC', key, sig, encoder.encode(data));
  }

  function hexToBytes(hex : string) {
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < bytes.length; i++) {
	  bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
	}
	return bytes;
  }
