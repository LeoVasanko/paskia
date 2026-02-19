"""Utility functions for HTML manipulation."""

import re

from paskia.fastapi.front import frontend
from paskia.util import vitedev


async def patched_html_response(request, filepath: str, status_code: int, **data_attrs):
    """Fetch HTML from vitedev and patch with data attributes.

    Strips caching/compression headers from request to get raw content,
    patches the HTML body with data attributes, and strips caching headers
    from response.

    Args:
        request: The FastAPI Request object
        filepath: Path to HTML file, e.g. "/int/forward/"
        status_code: HTTP status code for the response
        **data_attrs: Key-value pairs for data attributes

    Returns:
        Patched Response object, or original response if not 200.
    """
    resp = await vitedev.handle(request, frontend, filepath)
    # Pass through non-200 responses
    if resp.status_code != 200:
        return resp
    # Patch HTML with data attrs and strip caching headers from response
    resp.body = patch_html_data_attrs(resp.body, **data_attrs)
    resp.status_code = status_code
    strip_headers = {b"etag", b"last-modified", b"content-length"}
    resp.raw_headers = [
        (k, v) for k, v in resp.raw_headers if k.lower() not in strip_headers
    ]
    return resp


def patch_html_data_attrs(html: bytes, **data_attrs: str) -> bytes:
    """Patch HTML by adding data attributes to the <html> tag.

    If an <html> tag exists, adds data attributes to it.
    If no <html> tag exists, prepends one with the data attributes.

    Args:
        html: The HTML content as bytes
        **data_attrs: Key-value pairs for data attributes (e.g., mode='reauth')

    Returns:
        Modified HTML as bytes

    Examples:
        >>> patch_html_data_attrs(b'<html><body>test</body></html>', mode='reauth')
        b'<html data-mode="reauth"><body>test</body></html>'

        >>> patch_html_data_attrs(b'<body>test</body>', mode='reauth')
        b'<html data-mode="reauth"><body>test</body>'
    """
    if not data_attrs:
        return html

    html_str = html.decode("utf-8")

    # Build the data attributes string
    attrs_str = " ".join(f'data-{key}="{value}"' for key, value in data_attrs.items())

    # Check if there's an <html> tag (case-insensitive, may have existing attributes)
    html_tag_pattern = re.compile(r"<html([^>]*)>", re.IGNORECASE)
    match = html_tag_pattern.search(html_str)

    if match:
        # Insert data attributes into existing <html> tag
        existing_attrs = match.group(1)
        new_tag = f"<html{existing_attrs} {attrs_str}>"
        html_str = html_tag_pattern.sub(new_tag, html_str, count=1)
    else:
        # Prepend <html> tag with data attributes
        html_str = f"<html {attrs_str}>" + html_str

    return html_str.encode("utf-8")
