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
        if request.url.path == "/healthz":
            return await call_next(request)

        if request.method == "POST" or request.method == "GET":
            auth_header = request.headers.get("Authorization")
            cloud_id_header = request.headers.get("X-Atlassian-Cloud-Id")

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








# class UserTokenMiddleware(BaseHTTPMiddleware):
#     """Middleware to extract Atlassian user tokens/credentials from Authorization headers."""

#     def __init__(
#         self, app: Any, mcp_server_ref: Optional["AtlassianMCP"] = None
#     ) -> None:
#         super().__init__(app)
#         self.mcp_server_ref = mcp_server_ref
#         if not self.mcp_server_ref:
#             logger.warning(
#                 "UserTokenMiddleware initialized without mcp_server_ref. Path matching for MCP endpoint might fail if settings are needed."
#             )

#     async def dispatch(
#         self, request: Request, call_next: RequestResponseEndpoint
#     ) -> JSONResponse:
#         logger.debug(
#             f"UserTokenMiddleware.dispatch: ENTERED for request path='{request.url.path}', method='{request.method}'"
#         )
#         mcp_server_instance = self.mcp_server_ref
#         if mcp_server_instance is None:
#             logger.debug(
#                 "UserTokenMiddleware.dispatch: self.mcp_server_ref is None. Skipping MCP auth logic."
#             )
#             return await call_next(request)

#         mcp_path = mcp_server_instance.settings.streamable_http_path.rstrip("/")
#         request_path = request.url.path.rstrip("/")
#         logger.debug(
#             f"UserTokenMiddleware.dispatch: Comparing request_path='{request_path}' with mcp_path='{mcp_path}'. Request method='{request.method}'"
#         )
#         if request_path == mcp_path and request.method == "POST":
#             auth_header = request.headers.get("Authorization")
#             cloud_id_header = request.headers.get("X-Atlassian-Cloud-Id")

#             token_for_log = mask_sensitive(
#                 auth_header.split(" ", 1)[1].strip()
#                 if auth_header and " " in auth_header
#                 else auth_header
#             )
#             logger.debug(
#                 f"UserTokenMiddleware: Path='{request.url.path}', AuthHeader='{mask_sensitive(auth_header)}', ParsedToken(masked)='{token_for_log}', CloudId='{cloud_id_header}'"
#             )

#             # Extract and save cloudId if provided
#             if cloud_id_header and cloud_id_header.strip():
#                 request.state.user_atlassian_cloud_id = cloud_id_header.strip()
#                 logger.debug(
#                     f"UserTokenMiddleware: Extracted cloudId from header: {cloud_id_header.strip()}"
#                 )
#             else:
#                 request.state.user_atlassian_cloud_id = None
#                 logger.debug(
#                     "UserTokenMiddleware: No cloudId header provided, will use global config"
#                 )

#             # Check for mcp-session-id header for debugging
#             mcp_session_id = request.headers.get("mcp-session-id")
#             if mcp_session_id:
#                 logger.debug(
#                     f"UserTokenMiddleware: MCP-Session-ID header found: {mcp_session_id}"
#                 )
#             if auth_header and auth_header.startswith("Bearer "):
#                 token = auth_header.split(" ", 1)[1].strip()
#                 if not token:
#                     return JSONResponse(
#                         {"error": "Unauthorized: Empty Bearer token"},
#                         status_code=401,
#                     )
#                 logger.debug(
#                     f"UserTokenMiddleware.dispatch: Bearer token extracted (masked): ...{mask_sensitive(token, 8)}"
#                 )
#                 request.state.user_atlassian_token = token
#                 request.state.user_atlassian_auth_type = "oauth"
#                 request.state.user_atlassian_email = None
#                 logger.debug(
#                     f"UserTokenMiddleware.dispatch: Set request.state (pre-validation): "
#                     f"auth_type='{getattr(request.state, 'user_atlassian_auth_type', 'N/A')}', "
#                     f"token_present={bool(getattr(request.state, 'user_atlassian_token', None))}"
#                 )
#             elif auth_header and auth_header.startswith("Token "):
#                 token = auth_header.split(" ", 1)[1].strip()
#                 if not token:
#                     return JSONResponse(
#                         {"error": "Unauthorized: Empty Token (PAT)"},
#                         status_code=401,
#                     )
#                 logger.debug(
#                     f"UserTokenMiddleware.dispatch: PAT (Token scheme) extracted (masked): ...{mask_sensitive(token, 8)}"
#                 )
#                 request.state.user_atlassian_token = token
#                 request.state.user_atlassian_auth_type = "pat"
#                 request.state.user_atlassian_email = (
#                     None  # PATs don't carry email in the token itself
#                 )
#                 logger.debug(
#                     "UserTokenMiddleware.dispatch: Set request.state for PAT auth."
#                 )
#             elif auth_header:
#                 logger.warning(
#                     f"Unsupported Authorization type for {request.url.path}: {auth_header.split(' ', 1)[0] if ' ' in auth_header else 'UnknownType'}"
#                 )
#                 return JSONResponse(
#                     {
#                         "error": "Unauthorized: Only 'Bearer <OAuthToken>' or 'Token <PAT>' types are supported."
#                     },
#                     status_code=401,
#                 )
#             else:
#                 logger.debug(
#                     f"No Authorization header provided for {request.url.path}. Will proceed with global/fallback server configuration if applicable."
#                 )
#         response = await call_next(request)
#         logger.debug(
#             f"UserTokenMiddleware.dispatch: EXITED for request path='{request.url.path}'"
#         )
#         return response