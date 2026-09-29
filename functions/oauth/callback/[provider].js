
import { randomToken, sha256Base64Url } from "../../_shared/crypto.js";
import {
  getCookie,
  clearTxCookie,
  buildSessionCookie,
} from "../../_shared/cookies.js";
import { getProvider } from "../../_shared/providers.js";
import { validateGoogleIdToken } from "../../_shared/oidc.js";

export async function onRequestGet(context) {
  const { request, params, env } = context;
  const providerName = params.provider;
  const provider = getProvider(providerName);

  if (!provider) {
    return new Response("Not found", { status: 404 });
  }

  const url = new URL(request.url);
  const error = url.searchParams.get("error");
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (error || !code || !state) {
    return new Response("Falha na autenticação", { status: 400 });
  }

  
  const transactionCookie = getCookie(request, "__Host-oauth-tx");
  if (!transactionCookie) {
    return new Response("Transação não encontrada (cookie ausente)", {
      status: 400,
    });
  }

  const idHash = await sha256Base64Url(transactionCookie);
  const now = Math.floor(Date.now() / 1000);

  const transaction = await env.DB.prepare(
    `SELECT * FROM oauth_transactions WHERE id_hash = ? AND expires_at > ?`
  )
    .bind(idHash, now)
    .first();

  if (!transaction) {
    return new Response("Transação inválida ou expirada", { status: 400 });
  }

 
  const stateHash = await sha256Base64Url(state);
  if (stateHash !== transaction.state_hash) {
   
    await env.DB.prepare(`DELETE FROM oauth_transactions WHERE id_hash = ?`)
      .bind(idHash)
      .run();
    return new Response("State inválido", { status: 400 });
  }

  
  await env.DB.prepare(`DELETE FROM oauth_transactions WHERE id_hash = ?`)
    .bind(idHash)
    .run();

  const baseUrl = env.PUBLIC_BASE_URL;
  const redirectUri = `${baseUrl}/oauth/callback/${providerName}`;
  const clientId =
    providerName === "google" ? env.GOOGLE_CLIENT_ID : env.GITHUB_CLIENT_ID;
  const clientSecret =
    providerName === "google"
      ? env.GOOGLE_CLIENT_SECRET
      : env.GITHUB_CLIENT_SECRET;

 
  const tokenResponse = await fetch(provider.tokenEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: redirectUri,
      grant_type: "authorization_code",
      code_verifier: transaction.code_verifier,
    }),
  });

    if (!tokenResponse.ok) {
    const errorBody = await tokenResponse.text();
    const debugInfo = {
      clientIdLength: clientId ? clientId.length : "undefined",
      clientIdPreview: clientId ? clientId.slice(0, 10) : "undefined",
      secretLength: clientSecret ? clientSecret.length : "undefined",
      secretDefined: !!clientSecret,
    };
    return new Response(
      `Falha ao trocar o código por token. Status: ${tokenResponse.status}. Corpo: ${errorBody}. Debug: ${JSON.stringify(debugInfo)}`,
      { status: 400 }
    );
  }

  const tokenData = await tokenResponse.json();

  let issuer, subject, email, displayName;

  if (providerName === "google") {
    
    const payload = await validateGoogleIdToken(
      tokenData.id_token,
      clientId,
      transaction.nonce
    );
    issuer = "https://accounts.google.com";
    subject = payload.sub;
    email = payload.email ?? null;
    displayName = payload.name ?? null;
  } else {
    
    if (!tokenData.access_token || !/^bearer$/i.test(tokenData.token_type)) {
      return new Response("Resposta de token inválida do GitHub", {
        status: 400,
      });
    }

    const userResponse = await fetch("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
        "User-Agent": "oauth-pages-lab",
      },
    });

    if (!userResponse.ok) {
      return new Response("Falha ao consultar perfil do GitHub", {
        status: 400,
      });
    }

    const githubUser = await userResponse.json();
    issuer = "https://github.com";
    subject = String(githubUser.id);
    email = githubUser.email ?? null;
    displayName = githubUser.name ?? githubUser.login ?? null;

   
    const revokeCredentials = btoa(`${clientId}:${clientSecret}`);
    await fetch(
      `https://api.github.com/applications/${clientId}/grant`,
      {
        method: "DELETE",
        headers: {
          Authorization: `Basic ${revokeCredentials}`,
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2026-03-10",
          "Content-Type": "application/json",
          "User-Agent": "oauth-pages-lab",
        },
        body: JSON.stringify({ access_token: tokenData.access_token }),
      }
    );

  }


  const sessionToken = randomToken();
  const sessionHash = await sha256Base64Url(sessionToken);
  const sessionExpiresAt = now + 28800; 

  await env.DB.prepare(
    `INSERT INTO sessions
      (id_hash, issuer, subject, email, display_name, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(sessionHash, issuer, subject, email, displayName, sessionExpiresAt, now)
    .run();


  const headers = new Headers();
  headers.append("Location", baseUrl);
  headers.append("Set-Cookie", clearTxCookie());
  headers.append("Set-Cookie", buildSessionCookie(sessionToken));

  return new Response(null, { status: 302, headers });
}
