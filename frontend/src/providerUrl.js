function rawAuthority(value) {
  const start = value.indexOf("://");
  if (start < 0) return "";
  const from = start + 3;
  const slash = value.indexOf("/", from);
  return value.slice(from, slash < 0 ? value.length : slash);
}

function isLoopback(hostname) {
  return hostname === "localhost"
    || hostname === "127.0.0.1"
    || hostname === "[::1]";
}

/**
 * Return the security-relevant API authority, or an empty string for unsafe URLs.
 * Paths are intentionally ignored; credentials, query strings and fragments are not.
 */
export function apiAuthority(value) {
  const raw = String(value || "").trim();
  const sourceAuthority = rawAuthority(raw);
  if (!raw || !sourceAuthority || raw.includes("?") || raw.includes("#")
    || sourceAuthority.includes("@") || sourceAuthority.endsWith(":")) {
    return "";
  }

  try {
    const parsed = new URL(raw);
    const scheme = parsed.protocol.toLowerCase();
    const hostname = parsed.hostname.toLowerCase().replace(/\.+$/, "");
    if (!hostname || parsed.username || parsed.password) return "";
    if (scheme !== "https:" && !(scheme === "http:" && isLoopback(hostname))) return "";

    const port = parsed.port || (scheme === "https:" ? "443" : "80");
    const portNumber = Number(port);
    if (!Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535) return "";
    return `${scheme}//${hostname}:${port}`;
  } catch {
    return "";
  }
}

export function sameApiAuthority(left, right) {
  const leftAuthority = apiAuthority(left);
  return !!leftAuthority && leftAuthority === apiAuthority(right);
}
