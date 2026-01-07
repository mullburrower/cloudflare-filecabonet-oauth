import { stateKey } from "../_lib/qb";

export const onRequest: PagesFunction<{ QBO_TOKENS: KVNamespace }> = async ({ env }) => {
    const clientId = (env.QB_CLIENT_ID ?? "").trim();
    const redirectUri = (env.QB_REDIRECT_URI ?? "").trim();
    const scope = "com.intuit.quickbooks.accounting";

    if (!clientId) return new Response("Missing QB_CLIENT_ID", { status: 500 });
    if (!redirectUri) return new Response("Missing QB_REDIRECT_URI", { status: 500 });

    const state = crypto.randomUUID();

    // Store state in KV for 10 minutes
    await env.QBO_TOKENS.put(stateKey(state), "1", { expirationTtl: 600 });

    const authorizeUrl =
        "https://appcenter.intuit.com/connect/oauth2" +
        `?client_id=${encodeURIComponent(clientId)}` +
        `&response_type=code` +
        `&scope=${encodeURIComponent(scope)}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&state=${encodeURIComponent(state)}`;

    // Also set state cookie for CSRF defense
    const headers = new Headers();
    headers.set("Location", authorizeUrl);
    headers.append(
        "Set-Cookie",
        `fcbn_state=${encodeURIComponent(state)}; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Lax`
    );

    return new Response(null, { status: 302, headers });
};
