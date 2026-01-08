import { isAccessTokenExpired, refreshAccessToken, tokenKey, QbTokenRecord, nowMs } from "../_lib/qb";

function unauthorized() {
    return new Response("Unauthorized", { status: 401 });
}

export const onRequest: PagesFunction<{ QB_TOKENS: KVNamespace }> = async (ctx) => {
    // Simple shared-secret auth between your API and Pages
    const expected = (ctx.env.FILECABONET_SHARED_SECRET  ?? "").trim();
    const got = ctx.request.headers.get("x-qbo-secret");
    if (!expected) return new Response("Server misconfigured: missing shared secret", { status: 500 });
    if (got !== expected) return unauthorized();

    const url = new URL(ctx.request.url);
    const realmId = url.searchParams.get("realmId");
    if (!realmId) return new Response("Missing realmId", { status: 400 });

    const stored = await ctx.env.QB_TOKENS.get(tokenKey(realmId));
    if (!stored) return new Response("Not connected", { status: 409 });

    const record = JSON.parse(stored) as any;
    if (!record.refresh_token) return new Response("Missing refresh_token in KV", { status: 500 });

    const clientId = (ctx.env.QB_CLIENT_ID ?? "").trim();
    const clientSecret = (ctx.env.QB_CLIENT_SECRET ?? "").trim();
    if (!clientId || !clientSecret) return new Response("Missing QB client env vars", { status: 500 });

    // If our _lib/qb already computes expiry, use that
    // Otherwise, refresh whenever access token is older than ~50 minutes
    const needsRefresh =
        isAccessTokenExpired(record as QbTokenRecord) ||
        (!record.expires_at && nowMs() - (record.obtained_at || 0) > 50 * 60 * 1000);

    if (!needsRefresh && record.access_token) {
        return new Response(
            JSON.stringify({ access_token: record.access_token, token_type: record.token_type, expires_in: record.expires_in }, null, 2),
            { status: 200, headers: { "content-type": "application/json" } }
        );
    }

    // Refresh
    const tokenResp = await fetch("https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer", {
        method: "POST",
        headers: {
            authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
            "content-type": "application/x-www-form-urlencoded",
            accept: "application/json",
        },
        body: new URLSearchParams({
            grant_type: "refresh_token",
            refresh_token: record.refresh_token,
        }),
    });

    const bodyText = await tokenResp.text();
    let json: any = null;
    try { json = JSON.parse(bodyText); } catch { json = { raw: bodyText }; }

    if (!tokenResp.ok) {
        return new Response(JSON.stringify({ error: "Refresh failed", status: tokenResp.status, body: json }, null, 2), {
            status: 500,
            headers: { "content-type": "application/json" },
        });
    }

    // Important: Intuit may or may not rotate refresh_token. Preserve the old one if none returned.
    const updated = {
        ...record,
        ...json,
        refresh_token: json.refresh_token ?? record.refresh_token,
        realmId,
        savedAtMs: nowMs(),
    };

    await ctx.env.QB_TOKENS.put(tokenKey(realmId), JSON.stringify(updated));

    return new Response(
        JSON.stringify(
            {
                access_token: updated.access_token,
                expires_in: updated.expires_in,
                token_type: updated.token_type,
            },
            null,
            2
        ),
        { status: 200, headers: { "Content-Type": "application/json" } }
    );
};
