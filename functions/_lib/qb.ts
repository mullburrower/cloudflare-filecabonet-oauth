export type QbTokenRecord = {
    realmId: string;
    access_token: string;
    refresh_token: string;
    token_type: string;
    expires_in: number;
    refresh_expires_in?: number;
    obtained_at: number; // epoch ms
};

export function nowMs() {
    return Date.now();
}

export function isAccessTokenExpired(rec: QbTokenRecord, skewSeconds = 60) {
    const expiresAt = rec.obtained_at + (rec.expires_in * 1000);
    return nowMs() >= (expiresAt - skewSeconds * 1000);
}

export function makeBasicAuth(clientId: string, clientSecret: string) {
    return `Basic ${btoa(`${clientId}:${clientSecret}`)}`;
}

export async function exchangeAuthCodeForTokens(opts: {
    code: string;
    redirectUri: string;
    clientId: string;
    clientSecret: string;
}) {
    const body = new URLSearchParams();
    body.set("grant_type", "authorization_code");
    body.set("code", opts.code);
    body.set("redirect_uri", opts.redirectUri);

    const resp = await fetch("https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer", {
        method: "POST",
        headers: {
            "Authorization": makeBasicAuth(opts.clientId, opts.clientSecret),
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        body,
    });

    if (!resp.ok) {
        const text = await resp.text();
        throw new Error(`Token exchange failed (${resp.status}): ${text}`);
    }

    return (await resp.json()) as {
        access_token: string;
        refresh_token: string;
        expires_in: number;
        x_refresh_token_expires_in?: number;
        token_type: string;
    };
}

export async function refreshAccessToken(opts: {
    refreshToken: string;
    clientId: string;
    clientSecret: string;
}) {
    const body = new URLSearchParams();
    body.set("grant_type", "refresh_token");
    body.set("refresh_token", opts.refreshToken);

    const resp = await fetch("https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer", {
        method: "POST",
        headers: {
            "Authorization": makeBasicAuth(opts.clientId, opts.clientSecret),
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        body,
    });

    if (!resp.ok) {
        const text = await resp.text();
        throw new Error(`Token refresh failed (${resp.status}): ${text}`);
    }

    return (await resp.json()) as {
        access_token: string;
        refresh_token: string;
        expires_in: number;
        x_refresh_token_expires_in?: number;
        token_type: string;
    };
}

export function tokenKey(realmId: string) {
    return `realm:${realmId}`;
}

export function stateKey(state: string) {
    return `state:${state}`;
}
