#!/usr/bin/env python3
"""Render the demo report published at https://amartinawi.github.io/eks-rbac-audit/

Builds a fictional cluster ("acme-prod") carrying a realistic spread of
misconfigurations, runs the real analysis and rendering pipeline over it, and
writes a self-contained HTML report.

Everything here is invented. The AWS account is the documentation-range
111122223333 and every role, namespace, and principal name was made up to
demonstrate a specific rule. No real cluster was involved.

    python3 examples/generate_demo.py [output.html]
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eksaudit import analyze, render
from eksaudit.collector import RawDump
from eksaudit.models import AccessEntry, AccessPolicy, CommandRecord, EksAccess

ACCOUNT = "111122223333"
REGION = "eu-west-1"
CLUSTER = "acme-prod"

BOOTSTRAP = {"kubernetes.io/bootstrapping": "rbac-defaults"}


# --------------------------------------------------------------------------- #
# The fictional cluster
# --------------------------------------------------------------------------- #
def cluster_role(name, rules, labels=None):
    metadata = {"name": name}
    if labels:
        metadata["labels"] = labels
    return {"metadata": metadata, "rules": rules}


def binding(name, role_name, subjects, kind="ClusterRole", labels=None):
    metadata = {"name": name}
    if labels:
        metadata["labels"] = labels
    return {
        "metadata": metadata,
        "roleRef": {"kind": kind, "name": role_name},
        "subjects": subjects,
    }


def aws_auth():
    """Node groups mapped correctly; humans and machines mapped carelessly."""
    map_roles = ""
    for group in ("web", "batch", "ingest"):
        map_roles += (
            "- groups:\n  - system:bootstrappers\n  - system:nodes\n"
            f"  rolearn: arn:aws:iam::{ACCOUNT}:role/acme-node-group-{group}\n"
            "  username: system:node:{{EC2PrivateDNSName}}\n"
        )
    for role, username, group in (
        ("acme-platform-engineer", "platform-engineer", "system:masters"),
        ("acme-ci-deploy-role", "ci-deploy", "system:masters"),
        ("acme-jenkins-runner", "jenkins-runner", "system:masters"),
        ("acme-billing-export-lambda", "billing-export", "platform-readonly"),
        ("acme-oncall-engineer", "oncall", "platform-readonly"),
    ):
        map_roles += (
            f"- groups:\n  - {group}\n"
            f"  rolearn: arn:aws:iam::{ACCOUNT}:role/{role}\n"
            f"  username: {username}\n"
        )

    # Written by a different tool, hence the quoted style — exactly the split
    # real clusters show.
    map_users = ""
    for user, group in (
        ("a.rivera", "system:masters"),
        ("m.chen", "system:masters"),
        ("s.patel", "system:masters"),
        ("build-bot", "system:masters"),
        ("qa-analyst", "platform-readonly"),
    ):
        map_users += (
            f'- "groups":\n  - "{group}"\n'
            f'  "userarn": "arn:aws:iam::{ACCOUNT}:user/{user}"\n'
            f'  "username": "{user}"\n'
        )

    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "aws-auth", "namespace": "kube-system"},
        "data": {"mapAccounts": "[]\n", "mapRoles": map_roles, "mapUsers": map_users},
    }


def cluster_roles():
    return (
        cluster_role("cluster-admin",
                     [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}], BOOTSTRAP),
        # Upstream defaults. They grant secrets and exec by design and must not
        # be flagged — the demo shows the tool getting this right.
        cluster_role("admin", [
            {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list", "watch"]},
            {"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["create"]},
        ], BOOTSTRAP),
        cluster_role("edit", [
            {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]},
            {"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["create"]},
        ], BOOTSTRAP),
        cluster_role("view",
                     [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}],
                     BOOTSTRAP),
        cluster_role("system:public-info-viewer",
                     [{"nonResourceURLs": ["/healthz", "/version"], "verbs": ["get"]}],
                     BOOTSTRAP),
        cluster_role("system:controller:expand-controller",
                     [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]}],
                     BOOTSTRAP),

        # R1 — the headline. Named read-only, hands out Secrets and pod exec.
        cluster_role("platform-readonly", [
            {"apiGroups": ["*"],
             "resources": ["deployments", "pods", "pods/log", "configmaps", "secrets",
                           "services", "namespaces", "horizontalpodautoscalers"],
             "verbs": ["get", "list", "watch"]},
            {"apiGroups": ["*"], "resources": ["pods/exec"], "verbs": ["create"]},
        ]),

        # R2 — admin-equivalent without claiming to be read-only.
        cluster_role("incident-debug", [
            {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]},
            {"apiGroups": [""], "resources": ["pods/exec", "pods/attach"], "verbs": ["create"]},
        ]),

        # R8 — a custom wildcard role.
        cluster_role("service-mesh-operator",
                     [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]),

        # R10 — privilege-escalation verbs.
        cluster_role("namespace-provisioner", [
            {"apiGroups": ["rbac.authorization.k8s.io"],
             "resources": ["clusterroles", "roles"], "verbs": ["bind", "escalate", "create"]},
            {"apiGroups": [""], "resources": ["namespaces"], "verbs": ["create", "delete"]},
        ]),

        # R11 — credential minting.
        cluster_role("workload-identity-broker", [
            {"apiGroups": [""], "resources": ["serviceaccounts/token"], "verbs": ["create"]},
            {"apiGroups": ["certificates.k8s.io"],
             "resources": ["certificatesigningrequests"], "verbs": ["create"]},
        ]),

        # R16 — controllers legitimately holding Secret access.
        cluster_role("ingress-controller", [
            {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list", "watch"]},
            {"apiGroups": [""], "resources": ["services", "endpoints"], "verbs": ["get", "list"]},
        ]),
        cluster_role("cert-manager-controller",
                     [{"apiGroups": [""], "resources": ["secrets"],
                       "verbs": ["get", "list", "watch", "create", "update"]}]),
        cluster_role("efs-csi-provisioner",
                     [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}]),
        cluster_role("metrics-reader",
                     [{"apiGroups": ["metrics.k8s.io"], "resources": ["pods", "nodes"],
                       "verbs": ["get", "list"]}]),
    )


def cluster_role_bindings():
    return (
        binding("cluster-admin", "cluster-admin",
                [{"kind": "Group", "name": "system:masters"}], labels=BOOTSTRAP),
        binding("eks:addon-cluster-admin", "cluster-admin",
                [{"kind": "User", "name": "eks:addon-manager"}]),
        binding("system:public-info-viewer", "system:public-info-viewer",
                [{"kind": "Group", "name": "system:unauthenticated"}], labels=BOOTSTRAP),
        binding("platform-readonly", "platform-readonly",
                [{"kind": "Group", "name": "platform-readonly"}]),
        binding("incident-debug", "incident-debug",
                [{"kind": "Group", "name": "sre"},
                 {"kind": "ServiceAccount", "name": "oncall-bot", "namespace": "observability"}]),
        binding("service-mesh-operator", "service-mesh-operator",
                [{"kind": "ServiceAccount", "name": "mesh-operator", "namespace": "mesh"}]),
        binding("namespace-provisioner", "namespace-provisioner",
                [{"kind": "ServiceAccount", "name": "provisioner", "namespace": "platform"}]),
        binding("workload-identity-broker", "workload-identity-broker",
                [{"kind": "ServiceAccount", "name": "identity-broker", "namespace": "platform"}]),
        binding("ingress-controller", "ingress-controller",
                [{"kind": "ServiceAccount", "name": "ingress-controller", "namespace": "ingress"}]),
        binding("cert-manager-controller", "cert-manager-controller",
                [{"kind": "ServiceAccount", "name": "cert-manager", "namespace": "cert-manager"}]),
        binding("efs-csi-provisioner", "efs-csi-provisioner",
                [{"kind": "ServiceAccount", "name": "efs-csi-controller", "namespace": "kube-system"}]),
        # R9 — the default ServiceAccount picked up a grant nobody reviews.
        binding("checkout-metrics", "metrics-reader",
                [{"kind": "ServiceAccount", "name": "default", "namespace": "checkout"}]),
    )


def roles_and_bindings():
    roles = (
        {"metadata": {"name": "ingress-controller", "namespace": "ingress"},
         "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]}]},
        {"metadata": {"name": "leader-election", "namespace": "kube-system"},
         "rules": [{"apiGroups": ["coordination.k8s.io"], "resources": ["leases"],
                    "verbs": ["get", "update", "create"]}]},
        {"metadata": {"name": "checkout-config", "namespace": "checkout"},
         "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get", "list"]}]},
    )
    bindings = (
        {"metadata": {"name": "ingress-controller", "namespace": "ingress"},
         "roleRef": {"kind": "Role", "name": "ingress-controller"},
         "subjects": [{"kind": "ServiceAccount", "name": "ingress-controller",
                       "namespace": "ingress"}]},
        {"metadata": {"name": "checkout-config", "namespace": "checkout"},
         "roleRef": {"kind": "Role", "name": "checkout-config"},
         "subjects": [{"kind": "ServiceAccount", "name": "checkout-api", "namespace": "checkout"}]},
    )
    return roles, bindings


def service_accounts():
    namespaces = ("default", "checkout", "payments", "ingress", "cert-manager",
                  "mesh", "platform", "observability", "kube-system")
    accounts = [{"metadata": {"name": "default", "namespace": ns}} for ns in namespaces]
    accounts += [
        {"metadata": {"name": name, "namespace": ns},
         "annotations": {"eks.amazonaws.com/role-arn": f"arn:aws:iam::{ACCOUNT}:role/{irsa}"}
         if irsa else {}}
        for name, ns, irsa in (
            ("ingress-controller", "ingress", "AcmeIngressControllerRole"),
            ("cert-manager", "cert-manager", "AcmeCertManagerRole"),
            ("efs-csi-controller", "kube-system", "AcmeEfsCsiRole"),
            ("mesh-operator", "mesh", None),
            ("provisioner", "platform", None),
            ("identity-broker", "platform", None),
            ("oncall-bot", "observability", None),
            ("checkout-api", "checkout", "AcmeCheckoutRole"),
            ("payments-worker", "payments", "AcmePaymentsRole"),
            ("aws-node", "kube-system", None),
            ("coredns", "kube-system", None),
            ("attachdetach-controller", "kube-system", None),
        )
    ]
    # Two workloads correctly opt out; the rest mount a token by default.
    accounts.append({"metadata": {"name": "log-shipper", "namespace": "observability"},
                     "automountServiceAccountToken": False})
    accounts.append({"metadata": {"name": "batch-runner", "namespace": "payments"},
                     "automountServiceAccountToken": False})
    return tuple(accounts)


def eks_access():
    """Access entries — admins the aws-auth ConfigMap cannot show."""
    return EksAccess(
        cluster_arn=f"arn:aws:eks:{REGION}:{ACCOUNT}:cluster/{CLUSTER}",
        authentication_mode="API_AND_CONFIG_MAP",
        access_entries=(
            AccessEntry(
                principal_arn=f"arn:aws:iam::{ACCOUNT}:role/acme-terraform-apply",
                username="terraform",
                policies=(AccessPolicy(name="AmazonEKSClusterAdminPolicy",
                                       scope_type="cluster"),),
            ),
            AccessEntry(
                principal_arn=f"arn:aws:iam::{ACCOUNT}:role/acme-break-glass",
                username="break-glass",
                policies=(AccessPolicy(name="AmazonEKSClusterAdminPolicy",
                                       scope_type="cluster"),),
            ),
            AccessEntry(
                principal_arn=f"arn:aws:iam::{ACCOUNT}:role/acme-developer",
                username="developer",
                policies=(AccessPolicy(name="AmazonEKSEditPolicy",
                                       scope_type="namespace",
                                       namespaces=("checkout", "payments")),),
            ),
            AccessEntry(
                principal_arn=f"arn:aws:iam::{ACCOUNT}:role/acme-node-group-web",
                entry_type="EC2_LINUX",
                username="system:node:{{EC2PrivateDNSName}}",
                kubernetes_groups=("system:bootstrappers", "system:nodes"),
            ),
        ),
        endpoint_public_access=True,
        public_access_cidrs=("0.0.0.0/0",),
        enabled_log_types=("api", "scheduler"),   # audit and authenticator are off
        platform_version="eks.14",
    )


def commands():
    """The commands a real run executes, for the methodology section."""
    context = f"arn:aws:eks:{REGION}:{ACCOUNT}:cluster/{CLUSTER}"
    kubectl = [
        ("version", "kubectl version"),
        ("cluster-info", "kubectl cluster-info"),
        ("aws-auth", "kubectl get cm aws-auth -n kube-system -o json"),
        ("crb", "kubectl get clusterrolebindings -o json"),
        ("cr", "kubectl get clusterroles -o json"),
        ("rb", "kubectl get rolebindings --all-namespaces -o json"),
        ("r", "kubectl get roles --all-namespaces -o json"),
        ("sa", "kubectl get serviceaccounts --all-namespaces -o json"),
        ("ns", "kubectl get namespaces -o json"),
        ("can-i-list", "kubectl auth can-i --list"),
        ("rbac-lookup", "kubectl rbac-lookup"),
        ("whocan-all", "kubectl who-can '*' '*'"),
        ("whocan-secrets", "kubectl who-can get secrets --all-namespaces"),
        ("whocan-pods", "kubectl who-can create pods --all-namespaces"),
        ("whocan-exec", "kubectl who-can create pods/exec --all-namespaces"),
        ("whocan-csr", "kubectl who-can create certificatesigningrequests"),
        ("kubeconfig", "kubectl config view --minify -o json"),
    ]
    records = [CommandRecord(label=label, command=f"{cmd} --context {context}", exit_code=0)
               for label, cmd in kubectl]

    aws = [
        ("aws-describe-cluster",
         f"aws eks describe-cluster --name {CLUSTER} --output json --region {REGION}"),
        ("aws-list-access-entries",
         f"aws eks list-access-entries --cluster-name {CLUSTER} --output json --region {REGION}"),
    ]
    for arn in ("acme-terraform-apply", "acme-break-glass", "acme-developer",
                "acme-node-group-web"):
        aws.append((
            "aws-describe-access-entry",
            f"aws eks describe-access-entry --cluster-name {CLUSTER} "
            f"--principal-arn arn:aws:iam::{ACCOUNT}:role/{arn} --output json --region {REGION}",
        ))
    records += [CommandRecord(label=label, command=cmd, exit_code=0) for label, cmd in aws]
    return tuple(records)


def build_dump():
    roles, role_bindings = roles_and_bindings()
    return RawDump(
        context=f"arn:aws:eks:{REGION}:{ACCOUNT}:cluster/{CLUSTER}",
        version_text=("Client Version: v1.32.2\nKustomize Version: v5.5.0\n"
                      "Server Version: v1.33.13-eks-8f14419\n"),
        cluster_info_text=("Kubernetes control plane is running at "
                           f"https://EXAMPLE0123456789.gr7.{REGION}.eks.amazonaws.com\n"),
        aws_auth=aws_auth(),
        cluster_roles=cluster_roles(),
        cluster_role_bindings=cluster_role_bindings(),
        roles=roles,
        role_bindings=role_bindings,
        service_accounts=service_accounts(),
        namespaces=tuple(
            {"metadata": {"name": n}} for n in
            ("cert-manager", "checkout", "default", "ingress", "kube-node-lease",
             "kube-public", "kube-system", "mesh", "observability", "payments", "platform")
        ),
        can_i_text=("Resources        Non-Resource URLs  Resource Names  Verbs\n"
                    "*.*              []                 []              [*]\n"),
        can_i_warning=("Warning: the list may be incomplete: webhook authorizer does not "
                       "support user rule resolution"),
        warnings=(),
    )


def main() -> int:
    output = sys.argv[1] if len(sys.argv) > 1 else "demo-report.html"
    # Fixed timestamp so regenerating the demo produces no diff noise.
    generated_at = datetime(2026, 8, 5, 9, 30, tzinfo=timezone.utc)

    result = analyze.analyze(build_dump(), eks=eks_access(), commands=commands())
    path = render.render_report(result, generated_at, output)

    counts = result.severity_counts
    print(f"wrote {path}")
    print(f"{len(result.findings)} findings: "
          + ", ".join(f"{counts[s]} {s.lower()}" for s in counts if counts[s]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
