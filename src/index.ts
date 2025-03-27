/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Bind resources to your worker in `wrangler.jsonc`. After adding bindings, a type definition for the
 * `Env` object can be regenerated with `npm run cf-typegen`.
 *
 * Learn more at https://developers.cloudflare.com/workers/
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

    // Valid request – let Cloudflare serve the asset
    return fetch(request);
  },
} satisfies ExportedHandler<Env>;


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