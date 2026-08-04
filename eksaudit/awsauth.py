"""Parse the EKS ``kube-system/aws-auth`` ConfigMap into normalised mappings.

The ConfigMap stores ``mapUsers`` / ``mapRoles`` / ``mapAccounts`` as YAML *strings*
inside its ``data`` block, and real clusters mix styles — a single cluster is
routinely seen with unquoted ``mapRoles`` and fully quoted ``mapUsers``, because
each was written by a different tool.

PyYAML handles both when it is importable. When it is not, a fallback parser
covers the aws-auth subset: a sequence of mappings whose values are scalars plus
one ``groups`` sequence. The two paths are asserted to agree in the test suite.
"""

from __future__ import annotations

from typing import Any, Optional

from .models import AuthMapping

try:  # pragma: no cover - exercised by whichever path the environment provides
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

# Keys holding the principal ARN, in the order aws-auth uses them.
_ARN_KEYS = ("rolearn", "userarn", "arn")


def parse_aws_auth(configmap: Optional[dict[str, Any]]) -> tuple[AuthMapping, ...]:
    """Return every principal mapping in the ConfigMap, ordered deterministically.

    Roles come before users only insofar as the ConfigMap lists them; within each
    block the original order is preserved so the report matches what an operator
    sees when they read the ConfigMap.
    """
    if not configmap:
        return ()
    data = configmap.get("data")
    if not isinstance(data, dict):
        return ()

    mappings: list[AuthMapping] = []
    for key, default_kind in (("mapRoles", "IAM role"), ("mapUsers", "IAM user")):
        for entry in _parse_block(data.get(key, "")):
            mapping = _to_mapping(entry, default_kind)
            if mapping is not None:
                mappings.append(mapping)
    return tuple(mappings)


def account_id(mappings: tuple[AuthMapping, ...]) -> str:
    """The AWS account id shared by the mapped principals, or empty.

    Cross-account mappings are legal, so the most common account wins rather
    than the first one seen.
    """
    tally: dict[str, int] = {}
    for mapping in mappings:
        found = mapping.account_id
        if found:
            tally[found] = tally.get(found, 0) + 1
    if not tally:
        return ""
    return max(sorted(tally), key=lambda acct: tally[acct])


def map_accounts(configmap: Optional[dict[str, Any]]) -> tuple[str, ...]:
    """Account ids in ``mapAccounts`` — every IAM principal in these is trusted."""
    if not configmap:
        return ()
    data = configmap.get("data")
    if not isinstance(data, dict):
        return ()
    raw = data.get("mapAccounts", "")
    parsed = _load_yaml(raw)
    if isinstance(parsed, list):
        return tuple(str(item).strip() for item in parsed if str(item).strip())
    return ()


# --------------------------------------------------------------------------- #
# Normalisation
# --------------------------------------------------------------------------- #
def _to_mapping(entry: dict[str, Any], default_kind: str) -> Optional[AuthMapping]:
    arn = ""
    for key in _ARN_KEYS:
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            arn = value.strip()
            break
    if not arn:
        return None

    groups = entry.get("groups") or entry.get("group") or []
    if isinstance(groups, str):
        groups = [groups]
    normalised_groups = tuple(str(g).strip() for g in groups if str(g).strip())

    return AuthMapping(
        arn=arn,
        kind=_kind_from_arn(arn, default_kind),
        username=str(entry.get("username", "") or "").strip(),
        groups=normalised_groups,
    )


def _kind_from_arn(arn: str, default_kind: str) -> str:
    """Trust the ARN over the block it came from — operators do mix them up."""
    if ":role/" in arn:
        return "IAM role"
    if ":user/" in arn:
        return "IAM user"
    return default_kind


# --------------------------------------------------------------------------- #
# YAML loading
# --------------------------------------------------------------------------- #
def _parse_block(text: Any) -> tuple[dict[str, Any], ...]:
    """Parse one ``mapUsers``/``mapRoles`` block into a tuple of dicts."""
    if not isinstance(text, str) or not text.strip():
        return ()
    parsed = _load_yaml(text)
    if isinstance(parsed, list):
        return tuple(item for item in parsed if isinstance(item, dict))
    return ()


def _load_yaml(text: Any) -> Any:
    if not isinstance(text, str) or not text.strip():
        return None
    if yaml is not None:
        try:
            return yaml.safe_load(text)
        except Exception:  # noqa: BLE001 - fall back rather than fail the audit
            pass
    return parse_simple_yaml_sequence(text)


def parse_simple_yaml_sequence(text: str) -> list[Any]:
    """Minimal YAML-sequence parser covering the aws-auth subset.

    Handles a top-level sequence of mappings whose values are scalars, plus a
    single nested sequence (``groups``). Quoted and unquoted keys and values are
    both accepted, as are inline empty sequences (``[]``).

    This is deliberately narrow: anything outside that shape is not aws-auth
    data, and guessing at it would be worse than returning nothing.
    """
    stripped_text = text.strip()
    if stripped_text in ("[]", "{}"):
        return []

    items: list[dict[str, Any]] = []
    current: Optional[dict[str, Any]] = None
    pending_list_key: Optional[str] = None

    for raw_line in text.splitlines():
        line = raw_line.replace("\t", "  ").rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip(" "))
        is_dash = stripped.startswith("- ") or stripped == "-"
        content = stripped[1:].strip() if is_dash else stripped

        # A dash at column zero starts a new mapping in the top-level sequence.
        if is_dash and indent == 0:
            if current is not None:
                items.append(current)
            current = {}
            pending_list_key = None
            if content:
                pending_list_key = _absorb(current, content)
            continue

        if current is None:
            continue

        # An indented dash is an element of the sequence opened by the last key.
        if is_dash:
            if pending_list_key is not None:
                current.setdefault(pending_list_key, []).append(_unquote(content))
            continue

        pending_list_key = _absorb(current, content)

    if current is not None:
        items.append(current)
    return items


def _absorb(target: dict[str, Any], content: str) -> Optional[str]:
    """Apply ``key: value`` to ``target``; return the key if it opened a sequence."""
    if ":" not in content:
        return None
    key, _, value = content.partition(":")
    key = _unquote(key.strip())
    value = value.strip()
    if value in ("", "|", ">"):
        target.setdefault(key, [])
        return key
    if value in ("[]", "{}"):
        target[key] = []
        return None
    target[key] = _unquote(value)
    return None


def _unquote(value: str) -> str:
    """Strip one layer of matching quotes, leaving inner content untouched."""
    text = value.strip()
    if len(text) >= 2 and text[0] in "\"'" and text[-1] == text[0]:
        return text[1:-1]
    return text
