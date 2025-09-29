"""Tests for the main MCP server implementation."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from starlette.requests import Request
from starlette.responses import JSONResponse

from mcp_atlassian.servers.main import UserTokenMiddleware, main_mcp

# Only use asyncio backend for anyio tests
pytestmark = pytest.mark.anyio(backends=["asyncio"])


@pytest.mark.anyio
async def test_run_server_stdio():
    """Test that main_mcp.run_async is called with stdio transport."""
    with patch.object(main_mcp, "run_async") as mock_run_async:
        mock_run_async.return_value = None
        await main_mcp.run_async(transport="stdio")
        mock_run_async.assert_called_once_with(transport="stdio")


@pytest.mark.anyio
async def test_run_server_sse():
    """Test that main_mcp.run_async is called with sse transport and correct port."""
    with patch.object(main_mcp, "run_async") as mock_run_async:
        mock_run_async.return_value = None
        test_port = 9000
        await main_mcp.run_async(transport="sse", port=test_port)
        mock_run_async.assert_called_once_with(transport="sse", port=test_port)


@pytest.mark.anyio
async def test_run_server_streamable_http():
    """Test that main_mcp.run_async is called with streamable-http transport and correct parameters."""
    with patch.object(main_mcp, "run_async") as mock_run_async:
        mock_run_async.return_value = None
        test_port = 9001
        test_host = "127.0.0.1"
        test_path = "/custom_mcp"
        await main_mcp.run_async(
            transport="streamable-http", port=test_port, host=test_host, path=test_path
        )
        mock_run_async.assert_called_once_with(
            transport="streamable-http", port=test_port, host=test_host, path=test_path
        )


@pytest.mark.anyio
async def test_run_server_invalid_transport():
    """Test that run_server raises ValueError for invalid transport."""
    # We don't need to patch run_async here as the error occurs before it's called
    with pytest.raises(ValueError) as excinfo:
        await main_mcp.run_async(transport="invalid")  # type: ignore

    assert "Unknown transport" in str(excinfo.value)
    assert "invalid" in str(excinfo.value)


@pytest.mark.anyio
async def test_health_check_endpoint():
    """Test the health check endpoint returns 200 and correct JSON response."""
    app = main_mcp.sse_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")

        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


@pytest.mark.anyio
async def test_sse_app_health_check_endpoint():
    """Test the /health endpoint on the SSE app returns 200 and correct JSON response."""
    app = main_mcp.sse_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


@pytest.mark.anyio
async def test_streamable_http_app_health_check_endpoint():
    """Test the /health endpoint on the Streamable HTTP app returns 200 and correct JSON response."""
    app = main_mcp.streamable_http_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


class TestUserTokenMiddleware:
    """Tests for the UserTokenMiddleware class."""

    @pytest.fixture
    def middleware(self):
        """Create a UserTokenMiddleware instance for testing."""
        mock_app = AsyncMock()
        # Create a mock MCP server to avoid warnings
        mock_mcp_server = MagicMock()
        # mock_mcp_server.settings.streamable_http_path = "/mcp"
        return UserTokenMiddleware(mock_app,
            jwks_uri="https://example.com/.well-known/jwks.json",
            issuer="https://example.com",
            audience="test-audience")

    @pytest.fixture
    def mock_request(self):
        """Create a mock request for testing."""
        request = MagicMock(spec=Request)
        request.url.path = "/mcp"
        request.method = "POST"
        
        # Create a mock headers object that behaves like a dict with get() method
        mock_headers = MagicMock()
        mock_headers.__getitem__ = lambda self, key: {}
        mock_headers.get = lambda key, default=None: None
        request.headers = mock_headers
        
        # Create a real state object that can be modified
        from types import SimpleNamespace
        request.state = SimpleNamespace()
        
        # Mock the body() method to return an async mock that returns empty JSON
        async def mock_body():
            return b"{}"
        request.body = AsyncMock(side_effect=mock_body)
        return request

    @pytest.fixture
    def mock_call_next(self):
        """Create a mock call_next function."""
        mock_response = JSONResponse({"test": "response"})
        call_next = AsyncMock(return_value=mock_response)
        return call_next

    @pytest.mark.anyio
    async def test_cloud_id_header_extraction_success(
        self, middleware, mock_request, mock_call_next
    ):
        """Test successful cloud ID header extraction."""
        # Setup request with cloud ID header
        def mock_headers_get(key, default=None):
            headers = {
                "authorization": "Bearer test-token",
                "x-atlassian-cloud-id": "test-cloud-id-123",
            }
            return headers.get(key.lower(), default)
        
        mock_request.headers.get = mock_headers_get
        mock_request.url.path = "/mcp"  # Make sure it's an MCP path
        mock_request.method = "POST"    # Make sure it's a POST

        # Mock the JWT verifier to return a successful verification
        from unittest.mock import AsyncMock, MagicMock
        mock_access_token = MagicMock()
        mock_access_token.claims = {"email": "test@example.com"}
        middleware.token_verifier.verify_token = AsyncMock(return_value=mock_access_token)

        result = await middleware.dispatch(mock_request, mock_call_next)

        # Verify cloud ID was extracted and stored in request state
        assert hasattr(mock_request.state, "user_atlassian_cloud_id")
        assert mock_request.state.user_atlassian_cloud_id == "test-cloud-id-123"

        # Verify the request was processed normally
        mock_call_next.assert_called_once_with(mock_request)
        assert result is not None
