"""Network safety policy for hostile email content.

Email-derived URLs are data only. They must never be fetched, followed, or
submitted to a URL reputation service. DNS lookups used by authentication and
infrastructure checks remain allowed through the dedicated DNS helpers.
"""

EMAIL_LINK_ACCESS_DISABLED = True
LINK_ACCESS_NOTICE = (
    "External link access is disabled: URLs are analyzed as hostile strings "
    "only; no browsing, redirects, downloads, or URL reputation requests are made."
)
