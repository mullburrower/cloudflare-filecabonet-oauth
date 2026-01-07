export const onRequest: PagesFunction = async ({ request, env, next }) => {
    const key = request.headers.get("x-filecabonet-key");
    if (!key || key !== (env.FILECABONET_SHARED_SECRET as string)) {
        return new Response("Unauthorized", { status: 401 });
    }
    return next();
};
