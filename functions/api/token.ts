import { isAccessTokenExpired, refreshAccessToken, tokenKey, QbTokenRecord, nowMs } from "../_lib/qb";

function unauthorized() {
    return new Response("Unauthorized", { status: 401 });
}

export const onRequest: PagesFunction<{ QBO_TOKENS: KVNamespace }> = async (ctx) => {
    // Simple shared-secret auth between your API and Pages
    const expected = ctx.env.QBO_SHARED_SECRET;
    const got = ctx.request.headers.get("x-qbo-secret");
    if (!expected || got !== expected) return unauthorized();

    const url = new URL(ctx.request.url);
    const realmId = url.searchParams.get("realmId");
    if (!realmId) return new Response("Missing realmId", { status: 400 });

    const stored = await ctx.env.QBO_TOKENS.get(`realm:${realmId}`);
    if (!stored) return new Response("Not connected", { status: 409 });

    const { refresh_token } = JSON.parse(stored) as { refresh_token: string };

    const clientId = ctx.env.QBO_CLIENT_ID!;
    const clientSecret = ctx.env.QBO_CLIENT_SECRET!;
    const basic = btoa(`${clientId}:${clientSecret}`);

    const body = new URLSearchParams();
    body.set("grant_type", "refresh_token");
    body.set("refresh_token", refresh_token);

    const tokenResp = await fetch("https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer", {
        method: "POST",
        headers: {
            Authorization: `Basic ${basic}`,
            "Content-Type": "application/x-www-form-urlencoded",
            Accept: "application/json",
        },
        body,
    });

    const json = await tokenResp.json<any>();
    if (!tokenResp.ok) return new Response(JSON.stringify(json, null, 2), { status: 500 });

    return new Response(
        JSON.stringify(
            {
                access_token: json.access_token,
                expires_in: json.expires_in,
                token_type: json.token_type,
            },
            null,
            2
        ),
        { status: 200, headers: { "Content-Type": "application/json" } }
    );
};
