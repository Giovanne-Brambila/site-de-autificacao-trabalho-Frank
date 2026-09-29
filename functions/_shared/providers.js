

export const PROVIDERS = {
  google: {
    authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenEndpoint: "https://oauth2.googleapis.com/token",
    scope: "openid email profile",
    usesNonce: true,
  },
  github: {
    authorizationEndpoint: "https://github.com/login/oauth/authorize",
    tokenEndpoint: "https://github.com/login/oauth/access_token",
    scope: null, 
    usesNonce: false,
  },
};

export function getProvider(name) {
  if (name !== "google" && name !== "github") {
    return null;
  }
  return PROVIDERS[name];
}
