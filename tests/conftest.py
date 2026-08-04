"""Shared fixtures. Everything here runs offline — no cluster, no AWS, no network."""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eksaudit.collector import RawDump

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "k8s")


def _items(directory: str, name: str) -> tuple:
    path = os.path.join(directory, f"{name}.json")
    if not os.path.exists(path):
        return ()
    with open(path, encoding="utf-8") as handle:
        return tuple(json.load(handle).get("items", ()))


def _object(directory: str, name: str):
    path = os.path.join(directory, f"{name}.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _text(directory: str, name: str) -> str:
    path = os.path.join(directory, name)
    if not os.path.exists(path):
        return ""
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def load_dump(directory: str, **overrides) -> RawDump:
    """Build a RawDump from a fixture directory, with optional field overrides."""
    base = dict(
        context="fixture-context",
        version_text=_text(directory, "version.txt"),
        cluster_info_text=_text(directory, "cluster-info.txt"),
        aws_auth=_object(directory, "aws-auth"),
        cluster_roles=_items(directory, "clusterroles"),
        cluster_role_bindings=_items(directory, "clusterrolebindings"),
        roles=_items(directory, "roles"),
        role_bindings=_items(directory, "rolebindings"),
        service_accounts=_items(directory, "serviceaccounts"),
        namespaces=_items(directory, "namespaces"),
        can_i_text="Resources  Non-Resource URLs  Resource Names  Verbs\n*.*  []  []  [*]\n",
    )
    base.update(overrides)
    return RawDump(**base)


@pytest.fixture
def fixtures_dir() -> str:
    return FIXTURES


@pytest.fixture
def raw_dump() -> RawDump:
    """The sanitized real cluster: a deliberately imperfect production cluster."""
    return load_dump(FIXTURES)


@pytest.fixture
def clean_dump() -> RawDump:
    """A well-configured cluster that must produce no CRITICAL or HIGH findings."""
    return load_dump(os.path.join(FIXTURES, "clean"))
