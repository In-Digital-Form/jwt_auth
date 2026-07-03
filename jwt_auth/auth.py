import frappe
import json
import jwt
import requests
from urllib.parse import quote

class SessionJWTAuth:
    def __init__(self, path=None, http_status_code=None):
        if not hasattr(frappe.local, "jwt_auth"):
            frappe.local.jwt_auth = JWTAuth(path, http_status_code)
        elif path or http_status_code:
            frappe.local.jwt_auth.update(path, http_status_code)

    def __getattr__(self, name):
        return getattr(frappe.local.jwt_auth, name)


class JWTAuth:
    def __init__(self, path=None, http_status_code=None):
        self.path = path
        self.http_status_code = http_status_code
        self.settings = frappe.get_cached_doc("JWT Auth Settings")
        self.claims = None
        self.user_email = None
        self.token = None
        self.redirect_to = None

    def auth(self):
        self.user_email = self.claims.get("email") if self.claims.get("email") else None
        if not self.user_email:
            return
        user_email = self.claims.get("email") if self.claims.get("email") else None
        if user_email:
            if frappe.db.exists("User", user_email):
                frappe.local.login_manager.login_as(user_email)
            elif self.settings.enable_user_reg:
                self.register_user(user_email)
                frappe.local.login_manager.login_as(user_email)
                if self.redirect_to:
                    frappe.session.data["jwt_auth_redirect"] = self.redirect_to
                    frappe.cache().set_value(f"jwt_original_location_{user_email}",frappe.local.request.path)

    def validate_auth(self):
        if self.can_auth():
            self.auth()

    def can_auth(self):
        if self.redirect_to:
            return False
        if not self.settings.enabled:
            return False
        if frappe.flags.get("jwt_logout_redirect", False):
            return False
        self.token = self.get_token(frappe.local.request)
        if self.token:
            self.token = self.token[len("Bearer "):].strip()
        if not self.token:
            return False
        if self.is_valid_token(self.token):
            return True

    def update(self, path, http_status_code):
        self.path = path
        self.http_status_code = http_status_code

    def get_login_url(self, redirect_to=None):
        login_url = self.settings.login_url
        if self.settings.redirect_param:
            redirect_to = redirect_to if redirect_to else self.path
            path = "%2F" + quote(redirect_to, safe="")
            if "?" in login_url:
                login_url += f"&{self.settings.redirect_param}={path}"
            else:
                login_url += f"?{self.settings.redirect_param}={path}"
        return login_url

    def get_logout_url(self, id_token_hint=None):
        logout_url = self.settings.logout_url
        params = []
        if id_token_hint:
            params.append(f"id_token_hint={quote(id_token_hint, safe='')}")
        elif self.settings.get("client_id"):
            params.append(f"client_id={quote(self.settings.client_id, safe='')}")
        if self.settings.redirect_param:
            redirect_to = frappe.utils.get_url()
            params.append(f"{self.settings.redirect_param}={quote(redirect_to, safe='')}")
        if params:
            logout_url += "?" + "&".join(params)
        return logout_url

    def get_public_keys(self):
        public_keys = []
        try:
            r = requests.get(self.settings.jwks_url, timeout=10)
            r.raise_for_status()
            jwk_set = r.json()
            for key_dict in jwk_set.get("keys", []):
                public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key_dict))
                public_keys.append(public_key)
        except requests.RequestException as e:
            frappe.log_error(
                message=f"JWKS request failed for {self.settings.jwks_url}: {e}",
                title="JWT Auth: JWKS fetch failed",
            )
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            frappe.log_error(
                message=f"JWKS parse failed for {self.settings.jwks_url}: {e}",
                title="JWT Auth: JWKS parse failed",
            )
        return public_keys

    def get_token(self, request):
        token = (
            request.cookies.get(self.settings.jwt_header)
            if request.cookies.get(self.settings.jwt_header)
            else (
                request.headers.get(self.settings.jwt_header)
                if request.headers.get(self.settings.jwt_header)
                else None
            )
        )
        return token

    def is_valid_token(self, token):
        keys = self.get_public_keys()
        secret = self.settings.get_password("jwt_private_secret")
        valid_token = False
        for key in keys:
            try:
                self.claims = jwt.decode(
                    token,
                    key=key,
                    audience=secret,
                    algorithms=["RS256"],
                )
                valid_token = True
                break
            except:
                pass
        return valid_token

    def register_user(self, user_email):
        if frappe.db.exists("User", user_email):
            return

        name = self.claims.get("name", "[Change Me]")
        preferred_username = self.claims.get("preferred_username", user_email)

        frappe.flags.jwt_auth_creating_user = True
        user = frappe.get_doc(
            {
                "doctype": "User",
                "email": user_email,
                "username": preferred_username,
                "first_name": name,
                "send_welcome_email": 0,
            }
        )
        user.insert(ignore_permissions=True)

        frappe.db.commit()


def handle_redirects(response=None, request=None):
    if not response or not hasattr(frappe, "session"):
        return
    
    if frappe.session.get("user") == "Guest" and frappe.flags.get("jwt_logout_redirect"):
        response.status_code = 302
        response.headers["Location"] = frappe.flags.pop("jwt_logout_redirect")
        return

    redirect_to = frappe.session.data.pop("jwt_auth_redirect", False)
    if not redirect_to and request.path == "/me":
        cache_key = f"jwt_original_location_{frappe.session.user}"
        redirect_to = frappe.cache().get_value(cache_key)
        frappe.cache().delete_value(cache_key)
    if redirect_to:
        response.status_code = 302
        response.headers["Location"] = redirect_to

    return


def _get_jwt_token_from_request():
    auth = SessionJWTAuth()
    token = auth.get_token(frappe.local.request)
    if token:
        token = token[len("Bearer "):].strip()
    return token


@frappe.whitelist()
def jwt_logout():
    auth = SessionJWTAuth()
    token = _get_jwt_token_from_request()
    frappe.local.login_manager.logout()
    frappe.flags.pop("jwt_logout_redirect", None)
    if auth.settings.enabled:
        return {"redirect_url": auth.get_logout_url(id_token_hint=token)}
    else:
        return {"redirect_url": "/login"}


@frappe.whitelist()
def on_logout():
    auth = SessionJWTAuth()
    token = _get_jwt_token_from_request()
    frappe.flags["jwt_logout_redirect"] = auth.get_logout_url(id_token_hint=token)


@frappe.whitelist()
def web_logout():
    auth = SessionJWTAuth()
    token = _get_jwt_token_from_request()
    frappe.local.login_manager.logout()
    if auth.settings.enabled:
        location = auth.get_logout_url(id_token_hint=token)
    else:
        location = "/login"
    frappe.local.response["type"] = "redirect"
    frappe.local.response["location"] = location


def validate_auth():
    SessionJWTAuth().validate_auth()
