
import { randomToken, sha256Base64Url } from "../../_shared/crypto.js";
import { buildTxCookie } from "../../_shared/cookies.js";
import { getProvider } from "../../_shared/providers.js";

export async function onRequestGet(context) {
  const { params, env } = context;
  const providerName = params.provider;
  const provider = getProvider(providerName);


 
  if (!provider) {
    return new Response("Not found", { status: 404 });
  }

  const baseUrl = env.PUBLIC_BASE_URL;
  const clientId =
    providerName === "google" ? env.GOOGLE_CLIENT_ID : env.GITHUB_CLIENT_ID;


  const transactionId = randomToken();
  const state = randomToken();
  const codeVerifier = randomToken();
  const nonce = provider.usesNonce ? randomToken() : null;

 
  const idHash = await sha256Base64Url(transactionId);
  const stateHash = await sha256Base64Url(state);


  const codeChallenge = await sha256Base64Url(codeVerifier);

  const expiresAt = Math.floor(Date.now() / 1000) + 600; 

  await env.DB.prepare(
    `INSERT INTO oauth_transactions
      (id_hash, provider, state_hash, nonce, code_verifier, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  )
    .bind(idHash, providerName, stateHash, nonce, codeVerifier, expiresAt)
    .run();

 
  const redirectUri = `${baseUrl}/oauth/callback/${providerName}`;
  const authUrl = new URL(provider.authorizationEndpoint);
  authUrl.searchParams.set("client_id", clientId);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  if (provider.scope) {
    authUrl.searchParams.set("scope", provider.scope);
  }
  if (nonce) {
    authUrl.searchParams.set("nonce", nonce);
  }

  return new Response(null, {
    status: 302,
    headers: {
      Location: authUrl.toString(),
      "Set-Cookie": buildTxCookie(transactionId),
    },
  });
}
