"""OIDC configuration validation and group-based role assignment."""

from __future__ import annotations

from urllib.parse import urlsplit

from authlib.integrations.starlette_client import OAuth


class OIDCLoginError(ValueError):
    """Raised when an identity cannot be safely mapped to an application role."""


def parse_group_ids(value: str | list[str] | tuple[str, ...]) -> tuple[str, ...]:
    if isinstance(value, str):
        values = value.replace(",", "\n").splitlines()
    elif isinstance(value, (list, tuple)) and all(isinstance(item, str) for item in value):
        values = value
    else:
        raise ValueError("Group IDs must be text values")
    groups = tuple(dict.fromkeys(item.strip() for item in values if item.strip()))
    if any(any(ord(character) < 32 for character in group) for group in groups):
        raise ValueError("Group IDs cannot contain control characters")
    return groups


def validate_oidc_config(issuer: str, client_id: str, admin_groups: str | list[str],
                         operator_groups: str | list[str], enabled: bool = True) -> dict:
    issuer = issuer.strip().rstrip("/")
    client_id = client_id.strip()
    parsed = urlsplit(issuer)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or any(ord(character) < 32 for character in issuer)):
        raise ValueError("OIDC issuer must be an HTTPS issuer URL without credentials, query, or fragment")
    if not client_id or len(client_id) > 512 or any(ord(character) < 32 for character in client_id):
        raise ValueError("OIDC client ID is required")
    try:
        parsed.port
    except ValueError as error:
        raise ValueError("OIDC issuer URL has an invalid port") from error
    administrators = parse_group_ids(admin_groups)
    operators = parse_group_ids(operator_groups)
    if enabled and not administrators:
        raise ValueError("Map at least one corporate group to the Administrator role before enabling OIDC")
    if set(administrators) & set(operators):
        raise ValueError("A group cannot map to both Administrator and Operator")
    return {"enabled": bool(enabled), "issuer": issuer, "client_id": client_id,
            "admin_groups": list(administrators), "operator_groups": list(operators)}


def create_oidc_client(config: dict, client_secret: str):
    if not config.get("enabled") or not client_secret:
        raise ValueError("Corporate OIDC sign-in is not configured")
    return OAuth().register(
        name="corporate",
        client_id=config["client_id"],
        client_secret=client_secret,
        server_metadata_url=config["issuer"].rstrip("/") + "/.well-known/openid-configuration",
        client_kwargs={"scope": "openid profile email", "code_challenge_method": "S256"},
    )


def role_from_claims(claims: dict, config: dict) -> str:
    if claims.get("_claim_names") or claims.get("hasgroups"):
        raise OIDCLoginError("The identity provider returned an overage group claim; configure groups assigned to this app")
    raw_groups = claims.get("groups")
    if not isinstance(raw_groups, list) or any(not isinstance(group, str) for group in raw_groups):
        raise OIDCLoginError("The identity provider did not return a groups claim")
    groups = set(raw_groups)
    if groups.intersection(config.get("admin_groups", ())):
        return "admin"
    if groups.intersection(config.get("operator_groups", ())):
        return "operator"
    raise OIDCLoginError("Your corporate account is not in an authorized application group")