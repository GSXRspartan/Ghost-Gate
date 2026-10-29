import { trustedBase } from "./trusted-url.js";

// The bot link is deliberately not an endpoint-discovery mechanism. These two destinations are
// deployment-controlled HTML configuration, validated again before a wallet is contacted.
export function configuredJoinEndpoints({ bridgeOrigin, claimOrigin, pageOrigin }) {
  const bridgeBase = trustedBase(bridgeOrigin, bridgeOrigin, pageOrigin);
  const claimUrl = trustedBase(`${claimOrigin}/claim`, claimOrigin, pageOrigin, { allowPath: true });
  return {
    bridgeBase,
    claimUrl: claimUrl && new URL(claimUrl).pathname === "/claim" ? claimUrl : null,
  };
}
