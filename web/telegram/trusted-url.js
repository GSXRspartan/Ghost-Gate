// Origins are configured by the operator in the page, never by the join link.
export function trustedBase(raw, configured, pageOrigin, { allowPath = false } = {}) {
  try {
    const url = new URL(raw);
    if (url.username || url.password || url.search || url.hash || (!allowPath && url.pathname !== "/")) return null;
    const page = new URL(pageOrigin);
    const loopbacks = ["localhost", "127.0.0.1", "[::1]"];
    const local = page.protocol === "http:" && loopbacks.includes(page.hostname)
      && url.protocol === "http:" && loopbacks.includes(url.hostname);
    const allowed = configured.split(",").map(s => s.trim()).filter(Boolean);
    if (!local && (url.protocol !== "https:" || !allowed.includes(url.origin))) return null;
    return url.origin + (allowPath ? url.pathname.replace(/\/$/, "") : "");
  } catch { return null; }
}
