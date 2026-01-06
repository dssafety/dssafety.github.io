export async function onRequest(context) {
  const { request, env, next } = context;

  const USER = env.BASIC_USER;
  const PASS = env.BASIC_PASS;

  if (!USER || !PASS) {
    return new Response("Auth not configured", { status: 500 });
  }

  const authHeader = request.headers.get("Authorization");

  if (!authHeader || !authHeader.startsWith("Basic ")) {
    return new Response("Authentication required", {
      status: 401,
      headers: {
        "WWW-Authenticate": 'Basic realm="Restricted"',
      },
    });
  }

  const decoded = atob(authHeader.replace("Basic ", ""));
  const [user, pass] = decoded.split(":");

  if (user !== USER || pass !== PASS) {
    return new Response("Unauthorized", {
      status: 401,
      headers: {
        "WWW-Authenticate": 'Basic realm="Restricted"',
      },
    });
  }

  return next();
}
