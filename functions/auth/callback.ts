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

export const onRequest: PagesFunction<{ QBO_TOKENS: KVNamespace }> = async (ctx) => {
    const url = new URL(ctx.request.url);
    const code = url.searchParams.get("code");
    const realmId = url.searchParams.get("realmId");

    if (!code || !realmId) return new Response("Missing code/realmId", { status: 400 });

    const clientId = ctx.env.QBO_CLIENT_ID!;
    const clientSecret = ctx.env.QBO_CLIENT_SECRET!;
    const redirectUri = ctx.env.QBO_REDIRECT_URI!;

    const basic = btoa(`${clientId}:${clientSecret}`);

    const body = new URLSearchParams();
    body.set("grant_type", "authorization_code");
    body.set("code", code);
    body.set("redirect_uri", redirectUri);

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

    // Store refresh token keyed by realm
    const record = {
        realmId,
        refresh_token: json.refresh_token,
        refresh_expires_in: json.x_refresh_token_expires_in,
        updated_at: new Date().toISOString(),
    };

    await ctx.env.QBO_TOKENS.put(`realm:${realmId}`, JSON.stringify(record));

    // redirect back to your “connected” page
    return Response.redirect(`${url.origin}/connected.html`, 302);
};
