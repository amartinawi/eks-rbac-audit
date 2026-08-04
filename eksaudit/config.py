"""Central configuration: severity model, rule constants, and naming heuristics.

Everything tunable lives here so no magic strings leak into the logic modules.
The analysis layer imports the frozen ``Thresholds`` dataclass; the CLI builds
one instance (optionally overriding values) and passes it down.
"""

from __future__ import annotations

from dataclasses import dataclass

# --------------------------------------------------------------------------- #
# Severity model
# --------------------------------------------------------------------------- #
# Ordered from most to least severe. The numeric rank drives sorting and the
# report's "top severity" computation.
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")

SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITY_ORDER)}

# Rendered colours for badges and the severity bar.
SEVERITY_COLORS = {
    "CRITICAL": "#b42318",
    "HIGH": "#dc6803",
    "MEDIUM": "#c3920a",
    "LOW": "#3a7afe",
    "INFORMATIONAL": "#5b6470",
}

# Severities always shown in the severity bar even when their count is zero, so
# the reader can see "0 critical" rather than wonder whether it was measured.
SEVERITY_ALWAYS_SHOWN = ("CRITICAL", "HIGH", "MEDIUM")


def severity_rank(severity: str) -> int:
    """Return the sort rank for a severity (lower == more severe).

    Unknown severities sort last so a typo never masquerades as critical.
    """
    return SEVERITY_RANK.get(severity, len(SEVERITY_ORDER))


# --------------------------------------------------------------------------- #
# Tunable thresholds
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Thresholds:
    """Tunables for the findings engine."""

    admin_threshold: int = 3          # standing cluster-admin principals before MEDIUM
    automount_ratio: float = 0.9      # share of SAs implicitly mounting tokens before LOW
    large_table_rows: int = 25        # collapse report tables longer than this


DEFAULT_THRESHOLDS = Thresholds()


# --------------------------------------------------------------------------- #
# Kubernetes built-ins
# --------------------------------------------------------------------------- #
# Objects whose names carry these prefixes ship with Kubernetes or EKS. They are
# excluded from "custom object" rules — flagging them would drown the report in
# noise the operator cannot act on.
BUILTIN_PREFIXES = ("system:", "eks:")

# Kubernetes labels its own default RBAC objects rather than relying on a name
# prefix: `admin`, `edit`, `view`, and `cluster-admin` carry no prefix but are
# upstream defaults, auto-reconciled by the API server on every restart. Treating
# them as operator-defined would flag `admin` and `edit` as dangerous custom
# roles on every cluster in existence.
BOOTSTRAP_LABEL = "kubernetes.io/bootstrapping"
BOOTSTRAP_LABEL_VALUE = "rbac-defaults"
AUTOUPDATE_ANNOTATION = "rbac.authorization.kubernetes.io/autoupdate"

# The upstream Kubernetes default binding for unauthenticated clients. It grants
# only /healthz, /version and API discovery, so it is reported as INFORMATIONAL
# rather than as an anonymous-access finding.
DEFAULT_ANONYMOUS_BINDINGS = frozenset({"system:public-info-viewer"})

ANONYMOUS_SUBJECTS = frozenset({"system:anonymous", "system:unauthenticated"})

CLUSTER_ADMIN_ROLE = "cluster-admin"
MASTERS_GROUP = "system:masters"
NODE_GROUPS = frozenset({"system:nodes", "system:bootstrappers"})
NODE_USERNAME_TEMPLATE = "system:node:{{EC2PrivateDNSName}}"
DEFAULT_SERVICE_ACCOUNT = "default"


# --------------------------------------------------------------------------- #
# Dangerous RBAC verbs / resources
# --------------------------------------------------------------------------- #
WRITE_VERBS = frozenset({"create", "update", "patch", "delete", "deletecollection", "*"})
READ_VERBS = frozenset({"get", "list", "watch", "*"})

# Pod subresources that yield code execution inside a running container.
EXEC_RESOURCES = frozenset({"pods/exec", "pods/attach", "pods/portforward"})

# Resources whose contents are credentials.
SECRET_RESOURCES = frozenset({"secrets"})

# Verbs that let a principal grant itself more permissions than it holds.
ESCALATION_VERBS = frozenset({"escalate", "bind"})

# Verbs that let a principal act as another identity.
IMPERSONATION_VERBS = frozenset({"impersonate"})
IMPERSONATION_RESOURCES = frozenset({"users", "groups", "serviceaccounts", "userextras"})

# Resources whose creation mints a usable credential.
CREDENTIAL_MINTING_RESOURCES = frozenset(
    {"serviceaccounts/token", "certificatesigningrequests"}
)


# --------------------------------------------------------------------------- #
# Naming heuristics
# --------------------------------------------------------------------------- #
# Tokens that make a role's name *claim* to be read-only. A role matching one of
# these while granting Secret read or pod exec is lying about its scope, which is
# what makes it dangerous: operators grant it believing it is harmless.
#
# Matched as whole tokens, not substrings, so "preview" is not read as "view" and
# "credential" is not read as "read". "reader" therefore needs its own entry —
# `pod-reader` is the canonical example Role in the Kubernetes documentation, so
# `<thing>-reader` is one of the most common read-only naming conventions there is.
READONLY_NAME_HINTS = (
    "read", "reader", "readers", "readonly", "read-only", "ro",
    "view", "viewer", "viewers", "get", "list", "watch", "observer", "spectator",
)

# Substrings suggesting a non-human (machine) principal. Machine identities with
# standing cluster-admin turn one leaked credential into full cluster takeover.
AUTOMATION_NAME_HINTS = (
    "ci", "cd", "cicd", "pipeline", "repo", "bot", "svc", "service",
    "automation", "jenkins", "gitlab", "github", "terraform", "lambda",
    "deploy", "runner", "agent", "worker", "job", "cron", "argo", "flux",
)

# Substrings identifying an EKS node-group IAM role.
NODE_ROLE_HINTS = ("node", "nodegroup", "worker", "eks-managed", "ng-", "-ng")

# Substrings identifying a controller/addon ServiceAccount, used to soften the
# "this SA can read Secrets" finding — controllers legitimately need some access.
CONTROLLER_SA_HINTS = (
    "controller", "operator", "csi", "ingress", "cert", "gateway",
    "provisioner", "addon", "manager", "webhook",
)


# --------------------------------------------------------------------------- #
# EKS control-plane access policies (read via the AWS API when available)
# --------------------------------------------------------------------------- #
# Access-entry policies that confer cluster-admin or near-admin. Compared against
# the tail of `arn:aws:eks::aws:cluster-access-policy/<name>`.
EKS_ADMIN_ACCESS_POLICIES = frozenset(
    {"AmazonEKSClusterAdminPolicy", "AmazonEKSAdminPolicy"}
)

# Authentication modes reported by `aws eks describe-cluster`.
AUTH_MODE_CONFIG_MAP = "CONFIG_MAP"
AUTH_MODE_API_AND_CONFIG_MAP = "API_AND_CONFIG_MAP"
AUTH_MODE_API = "API"

# Control-plane log types that make an authentication audit possible after the fact.
REQUIRED_LOG_TYPES = ("audit", "authenticator")

OPEN_CIDR = "0.0.0.0/0"


# --------------------------------------------------------------------------- #
# Runtime defaults
# --------------------------------------------------------------------------- #
DEFAULT_TIMEOUT_SECONDS = 60
KREW_PLUGINS = ("rbac-lookup", "who-can")
