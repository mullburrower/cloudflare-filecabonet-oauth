// functions/auth/connect.ts
export const onRequest: PagesFunction = async (context) => {
    const { env } = context;

    const clientId = env.QB_CLIENT_ID as string;
    const redirectUri = env.QB_REDIRECT_URI as string; // e.g. https://<proj>.pages.dev/auth/callback
    const scope = "com.intuit.quickbooks.accounting";
    const state = crypto.randomUUID();

    // You *should* store state somewhere (KV) for real CSRF protection.
    // For now, keep it simple for exploratory testing.

    const authorizeUrl =
        "https://appcenter.intuit.com/connect/oauth2" +
        `?client_id=${encodeURIComponent(clientId)}` +
        `&response_type=code` +
        `&scope=${encodeURIComponent(scope)}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&state=${encodeURIComponent(state)}`;

    return Response.redirect(authorizeUrl, 302);
};
