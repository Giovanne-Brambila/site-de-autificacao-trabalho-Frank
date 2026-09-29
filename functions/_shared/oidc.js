

const GOOGLE_ISSUER = "https://accounts.google.com";
const DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration";

function base64UrlToUint8Array(base64url) {
  const padded = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  const binary = atob(padded + pad);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function base64UrlDecodeJson(base64url) {
  const bytes = base64UrlToUint8Array(base64url);
  const text = new TextDecoder().decode(bytes);
  return JSON.parse(text);
}


export async function validateGoogleIdToken(idToken, expectedAudience, expectedNonce) {
  const parts = idToken.split(".");
  if (parts.length !== 3) {
    throw new Error("id_token com formato inválido");
  }

  const [headerB64, payloadB64, signatureB64] = parts;
  const header = base64UrlDecodeJson(headerB64);
  const payload = base64UrlDecodeJson(payloadB64);

  if (header.alg !== "RS256") {
    throw new Error("Algoritmo inesperado no header do id_token");
  }


  const discoveryResponse = await fetch(DISCOVERY_URL);
  if (!discoveryResponse.ok) {
    throw new Error("Falha ao obter documento de descoberta OIDC");
  }
  const discovery = await discoveryResponse.json();


  const jwksResponse = await fetch(discovery.jwks_uri);
  if (!jwksResponse.ok) {
    throw new Error("Falha ao obter JWKS");
  }
  const jwks = await jwksResponse.json();

  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  if (!jwk) {
    throw new Error("Chave pública correspondente não encontrada no JWKS");
  }

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );

  
  const signedData = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = base64UrlToUint8Array(signatureB64);

  const isValid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    publicKey,
    signature,
    signedData
  );

  if (!isValid) {
    throw new Error("Assinatura do id_token é inválida");
  }

 
  const now = Math.floor(Date.now() / 1000);

  if (payload.iss !== GOOGLE_ISSUER && payload.iss !== `https://${GOOGLE_ISSUER.replace("https://", "")}`) {
    if (payload.iss !== "https://accounts.google.com") {
      throw new Error("Emissor (iss) inesperado");
    }
  }
  if (payload.aud !== expectedAudience) {
    throw new Error("Audiência (aud) inesperada");
  }
  if (typeof payload.exp !== "number" || payload.exp < now) {
    throw new Error("id_token expirado");
  }
  if (typeof payload.iat !== "number" || payload.iat > now + 60) {
    throw new Error("id_token emitido no futuro (iat inválido)");
  }
  if (payload.nonce !== expectedNonce) {
    throw new Error("Nonce não confere");
  }

  return payload; 
}
