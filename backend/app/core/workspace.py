import re
import secrets

from fastapi import Request

# There are no user accounts, so each browser gets an unguessable workspace id
# in a cookie. Everything a visitor stores or reads is filtered by it, which
# keeps one visitor's scans out of another's history, search, and patch context.
WORKSPACE_COOKIE = "cg_workspace"
WORKSPACE_MAX_AGE = 365 * 24 * 3600

_WORKSPACE_RE = re.compile(r"^[0-9a-f]{32}$")


async def assign_workspace(request: Request, call_next):
    workspace_id = request.cookies.get(WORKSPACE_COOKIE, "")
    is_new = not _WORKSPACE_RE.match(workspace_id)
    if is_new:
        workspace_id = secrets.token_hex(16)
    request.state.workspace_id = workspace_id

    response = await call_next(request)

    if is_new:
        # Behind a TLS-terminating proxy the app itself only sees http.
        scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
        response.set_cookie(
            WORKSPACE_COOKIE,
            workspace_id,
            max_age=WORKSPACE_MAX_AGE,
            httponly=True,
            samesite="lax",
            secure=scheme == "https",
        )
    return response


def get_workspace_id(request: Request) -> str:
    return request.state.workspace_id
