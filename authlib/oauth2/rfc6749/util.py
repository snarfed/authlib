import base64
import binascii
from urllib.parse import unquote

from authlib.common.encoding import to_unicode
from authlib.common.urls import add_params_to_uri
from authlib.common.urls import quote_url

from .errors import InvalidRequestError


def list_to_scope(scope):
    """Convert a list of scopes to a space separated string."""
    if isinstance(scope, (set, tuple, list)):
        return " ".join([to_unicode(s) for s in scope])
    if scope is None:
        return scope
    return to_unicode(scope)


def scope_to_list(scope):
    """Convert a space separated string to a list of scopes."""
    if isinstance(scope, (tuple, list, set)):
        return [to_unicode(s) for s in scope]
    elif scope is None:
        return None
    return scope.strip().split()


def extract_basic_authorization(headers):
    auth = headers.get("Authorization")
    if not auth or " " not in auth:
        return None, None

    auth_type, auth_token = auth.split(None, 1)
    if auth_type.lower() != "basic":
        return None, None

    try:
        query = to_unicode(base64.b64decode(auth_token))
    except (binascii.Error, TypeError):
        return None, None
    if ":" in query:
        username, password = query.split(":", 1)
        return unquote(username), unquote(password)
    return query, None


def create_response_mode_response(redirect_uri, params, response_mode):
    if response_mode == "form_post":
        tpl = (
            "<html><head><title>Redirecting</title></head>"
            '<body onload="javascript:document.forms[0].submit()">'
            '<form method="post" action="{}">{}</form></body></html>'
        )
        inputs = "".join(
            [
                f'<input type="hidden" name="{quote_url(k)}" value="{quote_url(v)}"/>'
                for k, v in params
            ]
        )
        body = tpl.format(quote_url(redirect_uri), inputs)
        return 200, body, [("Content-Type", "text/html; charset=utf-8")]

    if response_mode == "query":
        uri = add_params_to_uri(redirect_uri, params, fragment=False)
    elif response_mode == "fragment":
        uri = add_params_to_uri(redirect_uri, params, fragment=True)
    else:
        raise InvalidRequestError("Invalid 'response_mode' value")

    return 302, "", [("Location", uri)]
