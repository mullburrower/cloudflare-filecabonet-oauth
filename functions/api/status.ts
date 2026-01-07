import { tokenKey } from "../_lib/qb";

export const onRequest: PagesFunction = async ({ request, env }) => {
    const url = new URL(request.url);
    const realmId = url.searchParams.get("realmId");
    if (!realmId) return new Response("Missing realmId", { status: 400 });

    const raw = await (env.QB_TOKENS as KVNamespace).get(tokenKey(realmId));
    return Response.json({ realmId, connected: !!raw });
};
