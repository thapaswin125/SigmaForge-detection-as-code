"""Shared pytest configuration.

Integration tests (Tier 2) are skipped unless --integration is passed or
ELASTIC_URL is set, so the default `pytest` run stays offline and fast.
"""

import os

import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--integration",
        action="store_true",
        default=False,
        help="run Tier 2 integration tests against a live Elasticsearch",
    )


def integration_enabled(config) -> bool:
    return config.getoption("--integration") or bool(os.environ.get("ELASTIC_URL"))


def pytest_collection_modifyitems(config, items):
    if integration_enabled(config):
        return
    skip = pytest.mark.skip(reason="integration tests need --integration or ELASTIC_URL")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip)
