import logging
from typing import Any, Optional
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse
from mcp_atlassian.utils.logging import mask_sensitive
from fastmcp.server.auth.providers.jwt import JWTVerifier

logger = logging.getLogger("mcp-atlassian.user_token_middleware")


class UserTokenMiddleware(BaseHTTPMiddleware):
    """Middleware to extract Atlassian user tokens/credentials from Authorization headers and verify JWT."""

    def __init__(
        self, app: Any, *, jwks_uri: str, issuer: str, audience: str, algorithm: str = "RS256"
    ) -> None:
        super().__init__(app)
        self.token_verifier = JWTVerifier(
            jwks_uri=jwks_uri,
            issuer=issuer,
            audience=audience,
            algorithm=algorithm,
        )

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> JSONResponse:
        logger.debug(
            f"UserTokenMiddleware.dispatch: ENTERED for request path='{request.url.path}', method='{request.method}'"
        )

        request_path = request.url.path.rstrip("/")
        if request.url.path == "/health":
            return await call_next(request)

        

        if request.method == "POST" or request.method == "GET":

            
            auth_header = request.headers.get("authorization")
            cloud_id_header = request.headers.get("X-Atlassian-Cloud-Id")
            print(f"auth_header: {auth_header}")
            if not auth_header:
                logger.debug(
                f"UserTokenMiddleware: Path='{request.url.path}', no auth header provided"
                )
                return JSONResponse(
                        {"error": "Unauthorized: Empty Authorization Header"},
                        status_code=401,
                    )

            token_for_log = mask_sensitive(
                auth_header.split(" ", 1)[1].strip()
                if auth_header and " " in auth_header
                else auth_header
            )
            logger.debug(
                f"UserTokenMiddleware: Path='{request.url.path}', AuthHeader='{mask_sensitive(auth_header)}', ParsedToken(masked)='{token_for_log}', CloudId='{cloud_id_header}'"
            )

            # Extract and save cloudId if provided
            if cloud_id_header and cloud_id_header.strip():
                request.state.user_atlassian_cloud_id = cloud_id_header.strip()
                logger.debug(
                    f"UserTokenMiddleware: Extracted cloudId from header: {cloud_id_header.strip()}"
                )
            else:
                request.state.user_atlassian_cloud_id = None
                logger.debug(
                    "UserTokenMiddleware: No cloudId header provided, will use global config"
                )

            # Check for mcp-session-id header for debugging
            mcp_session_id = request.headers.get("mcp-session-id")
            if mcp_session_id:
                logger.debug(
                    f"UserTokenMiddleware: MCP-Session-ID header found: {mcp_session_id}"
                )
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.split(" ", 1)[1].strip()
                if not token:
                    return JSONResponse(
                        {"error": "Unauthorized: Empty Bearer token"},
                        status_code=401,
                    )
                logger.debug(
                    f"UserTokenMiddleware.dispatch: Bearer token extracted (masked): ...{mask_sensitive(token, 8)}"
                )
                # JWT verification
                try:
                    access_token = await self.token_verifier.verify_token(token)
                    request.state.user_atlassian_token = token
                    request.state.user_atlassian_auth_type = "oauth"
                    request.state.user_atlassian_email = access_token.claims.get("email") if access_token else None
                    logger.debug(
                        f"UserTokenMiddleware.dispatch: JWT verified, email={getattr(request.state, 'user_atlassian_email', None)}"
                    )
                except Exception as e:
                    logger.warning(f"JWT verification failed: {e}")
                    return JSONResponse(
                        {"error": "Unauthorized: Invalid JWT token"},
                        status_code=401,
                    )
            elif auth_header:
                logger.warning(
                    f"Unsupported Authorization type for {request_path}: {auth_header.split(' ', 1)[0] if ' ' in auth_header else 'UnknownType'}"
                )
                return JSONResponse(
                    {
                        "error": "Unauthorized: Only 'Bearer <OAuthToken>' or 'Token <PAT>' types are supported."
                    },
                    status_code=401,
                )
            else:
                logger.debug(
                    f"No Authorization header provided for {request_path}. Will proceed with global/fallback server configuration if applicable."
                )
        response = await call_next(request)
        logger.debug(
            f"UserTokenMiddleware.dispatch: EXITED for request path='{request_path}'"
        )
        return response
