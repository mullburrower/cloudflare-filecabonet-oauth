// functions/auth/callback.ts
type TokenResponse = {
    access_token: string;
    refresh_token: string;
    expires_in: number;
    x_refresh_token_expires_in?: number;
    token_type: string;
};

export const onRequest: PagesFunction = async (context) => {
    const { request, env } = context;
    const url = new URL(request.url);

    const code = url.searchParams.get("code");
    const realmId = url.searchParams.get("realmId");

    if (!code || !realmId) {
        return new Response("Missing code or realmId", { status: 400 });
    }

    const clientId = env.QB_CLIENT_ID as string;
    const clientSecret = env.QB_CLIENT_SECRET as string;
    const redirectUri = env.QB_REDIRECT_URI as string;

    const basic = btoa(`${clientId}:${clientSecret}`);

    const body = new URLSearchParams();
    body.set("grant_type", "authorization_code");
    body.set("code", code);
    body.set("redirect_uri", redirectUri);

    // Token endpoint (production):
    const tokenUrl = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer";

    const resp = await fetch(tokenUrl, {
        method: "POST",
        headers: {
            "Authorization": `Basic ${basic}`,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        body,
    });

    if (!resp.ok) {
        const text = await resp.text();
        return new Response(`Token exchange failed: ${resp.status}\n${text}`, { status: 500 });
    }

    const tokens = (await resp.json()) as TokenResponse;

    // For exploratory testing, just show a success page.
    // IMPORTANT: do NOT display tokens in a real app.
    return Response.redirect(`/connected.html?realmId=${encodeURIComponent(realmId)}`, 302);
};
