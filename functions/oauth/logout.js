
import { sha256Base64Url } from "../_shared/crypto.js";
import { getCookie, clearSessionCookie } from "../_shared/cookies.js";

export async function onRequestPost(context) {
  const { request, env } = context;

  const origin = request.headers.get("Origin");
  if (origin !== env.PUBLIC_BASE_URL) {
    return new Response("Origem inválida", {
      status: 403,
      headers: { "Cache-Control": "no-store" },
    });
  }

  const sessionCookie = getCookie(request, "__Host-session");
  if (sessionCookie) {
    const sessionHash = await sha256Base64Url(sessionCookie);
    await env.DB.prepare(`DELETE FROM sessions WHERE id_hash = ?`)
      .bind(sessionHash)
      .run();
  }

  return new Response(null, {
    status: 302,
    headers: {
      Location: env.PUBLIC_BASE_URL,
      "Set-Cookie": clearSessionCookie(),
      "Cache-Control": "no-store",
    },
  });
}
