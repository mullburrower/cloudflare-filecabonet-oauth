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

export const onRequestGet: PagesFunction<{ QB_TOKENS: KVNamespace }> = async (context) => {
    const url = new URL(context.request.url);

    const code = url.searchParams.get("code");
    const realmId = url.searchParams.get("realmId");
    const state = url.searchParams.get("state");

    if (!code) return new Response("Missing ?code", { status: 400 });
    if (!realmId) return new Response("Missing ?realmId", { status: 400 });
    if (!state) return new Response("Missing ?state", { status: 400 });

    const clientId = (context.env.QB_CLIENT_ID ?? "").trim();
    const clientSecret = (context.env.QB_CLIENT_SECRET ?? "").trim();
    const redirectUri = (context.env.QB_REDIRECT_URI ?? "").trim();

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

    // CSRF defense: cookie state + KV state must match query state
    const cookieState = getCookie(context.request, "fcbn_state");
    if (!cookieState || cookieState !== state) {
        return new Response(JSON.stringify({ error: "Bad state (cookie mismatch)" }), {
            status: 400,
            headers: { "content-type": "application/json" },
        });
    }

    const stateExists = await context.env.QB_TOKENS.get(stateKey(state));
    if (!stateExists) {
        return new Response(JSON.stringify({ error: "Bad state (expired or missing)" }), {
            status: 400,
            headers: { "content-type": "application/json" },
        });
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

    const bodyText = await tokenResp.text();
    let tokenJson: any = null;
    try {
        tokenJson = JSON.parse(bodyText);
    } catch {
        tokenJson = { raw: bodyText };
    }

    if (!tokenResp.ok) {
        return new Response(
            JSON.stringify(
                {
                    error: "Token exchange failed",
                    status: tokenResp.status,
                    body: tokenJson,
                    hints: [
                        "Are QB_CLIENT_ID / QB_CLIENT_SECRET set in *Production* env (or Preview, if using preview URL)?",
                        "Does QB_REDIRECT_URI exactly match the Redirect URI configured in Intuit?",
                        "Are you using Production keys for a real company (and Dev keys only for sandbox)?",
                    ],
                },
                null,
                2
            ),
            { status: 500, headers: { "content-type": "application/json" } }
        );
    }

    await context.env.QB_TOKENS.put(
        tokenKey(realmId),
        JSON.stringify({
            ...tokenJson,
            realmId,
            savedAtMs: nowMs(),
        })
    );

    // burn state + clear cookie
    await context.env.QB_TOKENS.delete(stateKey(state));

    const headers = new Headers();
    headers.set("content-type", "text/html; charset=utf-8");
    headers.append("Set-Cookie", `fcbn_state=; Path=/; Max-Age=0; HttpOnly; Secure; SamesSite=Lax`);

    return new Response(bodyText, { status: 200, headers: { "content-type": "application/json" } });
};