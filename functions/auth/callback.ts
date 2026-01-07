import { exchangeAuthCodeForTokens, nowMs, tokenKey, stateKey, QbTokenRecord } from "../_lib/qb";

function getCookie(req: Request, name: string) {
    const raw = req.headers.get("Cookie") || "";
    const parts = raw.split(";").map((p) => p.trim());
    for (const p of parts) {
        const [k, ...rest] = p.split("=");
        if (k === name) return decodeURIComponent(rest.join("="));
    }
    return null;
}

export const onRequestGet: PagesFunction = async (context) => {
    const url = new URL(context.request.url);

    const code = url.searchParams.get("code");
    const realmId = url.searchParams.get("realmId");

    const clientId = (context.env.QB_CLIENT_ID ?? "").trim();
    const clientSecret = (context.env.QB_CLIENT_SECRET ?? "").trim();
    const redirectUri = (context.env.QB_REDIRECT_URI ?? "").trim();

    if (!code) return new Response("Missing ?code", { status: 400 });
    if (!realmId) return new Response("Missing ?realmId", { status: 400 });

    const missing = [
        !clientId ? "QB_CLIENT_ID" : null,
        !clientSecret ? "QB_CLIENT_SECRET" : null,
        !redirectUri ? "QB_REDIRECT_URI" : null,
    ].filter(Boolean);

    if (missing.length) {
        return new Response(
            JSON.stringify({ error: "Missing Cloudflare env vars", missing }),
            { status: 500, headers: { "content-type": "application/json" } }
        );
    }

    const tokenResp = await fetch("https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer", {
        method: "POST",
        headers: {
            "content-type": "application/x-www-form-urlencoded",
            "accept": "application/json",
            "authorization": `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
        },
        body: new URLSearchParams({
            grant_type: "authorization_code",
            code,
            redirect_uri: redirectUri,
        }),
    });

    const tokenJson = await tokenResp.json();
    await context.env.QBO_TOKENS.put(
        realmId,
        JSON.stringify({
            ...tokenJson,
            realmId,
            savedAt: new Date().toISOString(),
        })
    )

    const bodyText = await tokenResp.text();

    if (!tokenResp.ok) {
        return new Response(
            JSON.stringify({
                error: "Token exchange failed",
                status: tokenResp.status,
                body: bodyText,
                hints: [
                    "Are QB_CLIENT_ID / QB_CLIENT_SECRET set in *Production* env (or Preview, if using preview URL)?",
                    "Does QB_REDIRECT_URI exactly match the Redirect URI configured in Intuit?",
                    "Are you using Production keys for a real company (and Dev keys only for sandbox)?",
                ],
            }),
            { status: 500, headers: { "content-type": "application/json" } }
        );
    }

    // TODO: store tokens somewhere (KV) instead of discarding them
    return new Response(bodyText, { status: 200, headers: { "content-type": "application/json" } });
};