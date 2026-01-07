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

export const onRequest: PagesFunction = async ({ request, env }) => {
    const url = new URL(request.url);
    const code = url.searchParams.get("code");
    const realmId = url.searchParams.get("realmId");
    const state = url.searchParams.get("state");

    if (!code || !realmId || !state) {
        return new Response("Missing code, realmId, or state", { status: 400 });
    }

    // Validate state against cookie + KV
    const cookieState = getCookie(request, "fcbn_state");
    if (!cookieState || cookieState !== state) {
        return new Response("Invalid state (cookie mismatch)", { status: 400 });
    }

    const kv = env.QB_TOKENS as KVNamespace;
    const stateExists = await kv.get(stateKey(state));
    if (!stateExists) {
        return new Response("Invalid state (expired or unknown)", { status: 400 });
    }

    // one-time use
    await kv.delete(stateKey(state));

    const clientId = env.QB_CLIENT_ID as string;
    const clientSecret = env.QB_CLIENT_SECRET as string;
    const redirectUri = env.QB_REDIRECT_URI as string;

    try {
        const tok = await exchangeAuthCodeForTokens({
            code,
            redirectUri,
            clientId,
            clientSecret,
        });

        const record: QbTokenRecord = {
            realmId,
            access_token: tok.access_token,
            refresh_token: tok.refresh_token,
            token_type: tok.token_type,
            expires_in: tok.expires_in,
            refresh_expires_in: tok.x_refresh_token_expires_in,
            obtained_at: nowMs(),
        };

        // Store token record by realm
        // (If you only ever use one company, you can also store under a fixed key.)
        await kv.put(tokenKey(realmId), JSON.stringify(record));

        // Clear cookie
        const headers = new Headers();
        headers.set("Location", `/connected.html?realmId=${encodeURIComponent(realmId)}`);
        headers.append(
            "Set-Cookie",
            `fcbn_state=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`
        );

        return new Response(null, { status: 302, headers });
    } catch (e: any) {
        return new Response(`Callback failed: ${e?.message ?? String(e)}`, { status: 500 });
    }
};
