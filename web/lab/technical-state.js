/*
 * Sanitised state for Privacy Lab's Technical view.
 *
 * This module deliberately accepts only published gate metadata and coarse lifecycle labels.
 * It has no place for a wallet address, challenge nonce, output id, signature, session token, or
 * verifier credential.  Keeping that boundary here makes the browser inspector useful without
 * turning it into a second credential transport.
 */

export const NOT_REPORTED = "not reported";

export function newTechnicalLifecycle() {
    return {
        challenge: "not requested",
        credential: "not submitted",
        verification: "not started",
        session: "not issued",
        replay: NOT_REPORTED,
        failure: null,
    };
}

export function advanceTechnicalLifecycle(lifecycle, update) {
    return { ...lifecycle, ...update };
}

// A view switch is presentation-only.  Keeping the lifecycle object means Simple/Technical
// toggles can never erase a completed proof or its issued-session summary.
export function switchTechnicalView(lifecycle, view) {
    return { lifecycle, view };
}

export function technicalSummaryRows(gate, lifecycle, bridgeStatus, thresholdText) {
    const unavailable = "unavailable / not reported";
    const value = (candidate) => candidate == null || candidate === "" ? unavailable : String(candidate);
    return [
        ["gate", value(gate && gate.gateId)],
        ["asset", value(gate && gate.symbol)],
        ["threshold", gate ? `${thresholdText} / ${gate.thresholdRaw} raw` : unavailable],
        ["network", value(gate && gate.network)],
        ["proof mode", value(gate && gate.proofMode)],
        ["policy version", value(gate && gate.policyVersion)],
        ["policy hash", value(gate && gate.policyHash)],
        ["relying site", value(gate && gate.relyingSite)],
        ["challenge", value(lifecycle && lifecycle.challenge)],
        ["credential", value(lifecycle && lifecycle.credential)],
        ["verification", value(lifecycle && lifecycle.verification)],
        ["session / access", value(lifecycle && lifecycle.session)],
        ["replay / freshness", value(lifecycle && lifecycle.replay)],
        ["bridge", value(bridgeStatus)],
        ...(lifecycle && lifecycle.failure ? [["failure", lifecycle.failure]] : []),
    ];
}
