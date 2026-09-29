


export function getCookie(request, name) {
  const header = request.headers.get("Cookie");
  if (!header) return null;

  const cookies = header.split(";").map((c) => c.trim());
  for (const cookie of cookies) {
    const [key, ...rest] = cookie.split("=");
    if (key === name) {
      return rest.join("=");
    }
  }
  return null;
}


export function buildTxCookie(value) {
  return `__Host-oauth-tx=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`;
}


export function clearTxCookie() {
  return `__Host-oauth-tx=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}


export function buildSessionCookie(value) {
  return `__Host-session=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`;
}


export function clearSessionCookie() {
  return `__Host-session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}
