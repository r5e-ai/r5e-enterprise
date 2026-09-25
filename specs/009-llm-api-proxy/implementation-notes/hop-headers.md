# Connection-specific header filtering (#11)

Both directions remove the fixed hop headers and every field named by all
case-insensitive, comma-separated Connection options, trimming HTTP space/tab
whitespace. Trailer is now correctly stripped; the previously stripped nonstandard
trailers alias remains for compatibility. Ordinary HTTP Upgrade is removed.
Remaining end-to-end fields preserve their original values and occurrences.
A normally end-to-end field nominated by Connection is hop-specific on that
message and is removed too.

Request trace/tenant injection and configured Host rewriting occur after filtering,
so client nominations cannot suppress gateway-owned fields. The reserved managed
route credential is removed from forwarding and diagnostics entirely, including
its prefix; provider credentials retain their existing handling. This small
suppression is included explicitly on main and imports no managed bridge modules.

The websocket_upgrade? option reconstructs exactly Connection: upgrade and
Upgrade: websocket after removing incoming options. WebSocketBridge already removes
these Mint-owned handshake fields before Mint.WebSocket.upgrade generates the
actual upstream pair. No arbitrary client connection option survives. Response
filtering still removes Content-Length and Transfer-Encoding before Plug regenerates
chunk framing; non-nominated response metadata and Content-Encoding remain unchanged.

Focused coverage includes repeated headers, mixed case, comma/OWS lists, every
nominated occurrence, credential preservation/removal as appropriate, trace spoofing,
ordinary Upgrade and reserved-route suppression. Local TCP fixtures exercise actual
Mint WebSocket handshake generation (following the caller's existing final filter)
and an actual Bandit chunked response with no stale length/trailer/nominated fields.
These fixtures use no provider, live authentication or managed activation.
