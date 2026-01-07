import { isAccessTokenExpired, refreshAccessToken, tokenKey, QbTokenRecord, nowMs } from "../_lib/qb";

export const onRequest: PagesFunction = async ({ request, env }) => {
    const url = new URL(request.url);
    const realmId = url.searchParams.get("realmId");
    if (!realmId) return new Response("Missing realmId", { status: 400 });

    const kv = env.QB_TOKENS as KVNamespace;
    const raw = await kv.get(tokenKey(realmId));
    if (!raw) return new Response("Not connected for that realmId", { status: 404 });

    const clientId = env.QB_CLIENT_ID as string;
    const clientSecret = env.QB_CLIENT_SECRET as string;

    let rec = JSON.parse(raw) as QbTokenRecord;

    if (isAccessTokenExpired(rec)) {
        const refreshed = await refreshAccessToken({
            refreshToken: rec.refresh_token,
            clientId,
            clientSecret,
        });

        rec = {
            ...rec,
            access_token: refreshed.access_token,
            refresh_token: refreshed.refresh_token ?? rec.refresh_token,
            token_type: refreshed.token_type,
            expires_in: refreshed.expires_in,
            refresh_expires_in: refreshed.x_refresh_token_expires_in ?? rec.refresh_expires_in,
            obtained_at: nowMs(),
        };

        await kv.put(tokenKey(realmId), JSON.stringify(rec));
    }

    return Response.json({
        realmId: rec.realmId,
        access_token: rec.access_token,
        token_type: rec.token_type,
        obtained_at: rec.obtained_at,
        expires_in: rec.expires_in,
    });
};
