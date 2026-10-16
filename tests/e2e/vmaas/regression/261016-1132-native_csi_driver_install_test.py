"""Exercise pinned provider CSI operator installation through the Stage 2 AAP job."""

from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import pytest

from tests.e2e.core.k8s_client import K8sClient
from tests.e2e.core.runner import env, poll_until, run_unchecked

pytestmark = [pytest.mark.regression, pytest.mark.requires_vmaas]

_DRIVER_INSTALL_TAG = "provider_csi_driver_install"
_OPERATORS: tuple[dict[str, Any], ...] = (
    {
        "subscription": "trident-operator",
        "namespace": "openshift-operators",
        "csv": "trident-operator.v26.6.2",
        "drivers": ("csi.trident.netapp.io",),
    },
    {
        "subscription": "vast-csi-operator",
        "namespace": "vast-csi-system",
        "csv": "vast-csi-operator.v2.6.8",
        "drivers": ("block.csi.vastdata.com",),
    },
)


def test_stage2_tag_installs_pinned_native_csi_operators(k8s_hub_client: K8sClient, test_run_id: str) -> None:
    """Install both block drivers with real AAP and OLM, without array credentials.

    The full-install VMaaS runner owns a disposable cluster. The cluster-scoped
    Operators installed here are left for that runner's cluster teardown.
    """
    for operator in _OPERATORS:
        assert not _resource_exists(
            resource="subscription", name=operator["subscription"], namespace=operator["namespace"]
        ), f"Expected a clean CI cluster; Subscription {operator['namespace']}/{operator['subscription']} exists"
        assert not _resource_exists(
            resource="clusterserviceversion", name=operator["csv"], namespace=operator["namespace"]
        ), f"Expected a clean CI cluster; CSV {operator['namespace']}/{operator['csv']} exists"
        for driver in operator["drivers"]:
            assert not _resource_exists(resource="csidriver", name=driver), (
                f"Expected a clean CI cluster; CSIDriver {driver} already exists"
            )

    route = k8s_hub_client.get_json(resource="route", name="osac-aap")
    route_host = route.get("spec", {}).get("host", "")
    assert route_host, "AAP route osac-aap has no host"

    secret = k8s_hub_client.get_json(resource="secret", name="osac-aap-api-token")
    encoded_token = secret.get("data", {}).get("token", "")
    assert encoded_token, "AAP API token Secret has no token key"
    token = base64.b64decode(encoded_token).decode("utf-8")

    prefix = env("OSAC_AAP_TEMPLATE_PREFIX", "osac")
    template_name = f"{prefix}-create-tenant-cluster-storage"
    templates = _controller_request(
        route_host=route_host, token=token, path=f"job_templates/?{urllib.parse.urlencode({'name': template_name})}"
    ).get("results", [])
    matching_templates = [item for item in templates if item.get("name") == template_name]
    assert len(matching_templates) == 1, f"Expected exactly one AAP template named {template_name}"

    tenant_name = f"e2e-native-csi-{test_run_id}"
    extra_vars = {
        "osac_job_vars": {
            "resource": {
                "apiVersion": "osac.openshift.io/v1alpha1",
                "kind": "Tenant",
                "metadata": {
                    "name": tenant_name,
                    "namespace": "osac-tenants",
                    "uid": f"00000000-0000-4000-8000-{test_run_id:0>12}",
                },
                "spec": {},
            },
            "storage_tier_definitions": [
                {"name": f"netapp-block-{test_run_id}", "provider": "netapp", "protocol": "block"},
                {"name": f"vast-block-{test_run_id}", "provider": "vast", "protocol": "block"},
            ],
        }
    }
    launched = _controller_request(
        route_host=route_host,
        token=token,
        path=f"job_templates/{matching_templates[0]['id']}/launch/",
        payload={"extra_vars": extra_vars, "job_tags": _DRIVER_INSTALL_TAG},
    )
    job_id = launched.get("job") or launched.get("id")
    assert job_id, "AAP did not return the launched job ID"

    job = poll_until(
        fn=lambda: _controller_request(route_host=route_host, token=token, path=f"jobs/{job_id}/"),
        until=lambda result: result.get("status") in {"successful", "failed", "error", "canceled"},
        retries=120,
        delay=15,
        description="Stage 2 provider-native CSI install job",
    )
    assert job.get("status") == "successful", f"AAP job {job_id} ended with status {job.get('status')}"

    for operator in _OPERATORS:
        subscription = k8s_hub_client.get_json(
            resource="subscription", name=operator["subscription"], namespace=operator["namespace"]
        )
        assert subscription.get("spec", {}).get("startingCSV") == operator["csv"]
        assert subscription.get("spec", {}).get("installPlanApproval") == "Manual"
        assert subscription.get("status", {}).get("installedCSV") == operator["csv"]

        install_plan_name = subscription.get("status", {}).get("installPlanRef", {}).get("name")
        assert install_plan_name, f"Subscription {operator['subscription']} has no InstallPlan reference"
        install_plan = k8s_hub_client.get_json(
            resource="installplan", name=install_plan_name, namespace=operator["namespace"]
        )
        assert operator["csv"] in install_plan.get("spec", {}).get("clusterServiceVersionNames", [])
        assert install_plan.get("spec", {}).get("approved") is True

        csv = k8s_hub_client.get_json(
            resource="clusterserviceversion", name=operator["csv"], namespace=operator["namespace"]
        )
        assert csv.get("status", {}).get("phase") == "Succeeded"

        for driver in operator["drivers"]:
            assert _resource_exists(resource="csidriver", name=driver), (
                f"AAP job succeeded but CSIDriver {driver} was not registered"
            )


def _controller_request(
    *, route_host: str, token: str, path: str, payload: dict[str, Any] | None = None
) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        f"https://{route_host}/api/controller/v2/{path}",
        data=body,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST" if body is not None else "GET",
    )
    context = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(request, context=context, timeout=30) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"AAP Controller API returned HTTP {error.code} for {path}") from None
    except urllib.error.URLError:
        raise RuntimeError(f"Could not connect to the AAP Controller API for {path}") from None


def _resource_exists(*, resource: str, name: str, namespace: str | None = None) -> bool:
    command = ["kubectl", "get", resource, name, "--as", "system:admin"]
    if namespace is not None:
        command.extend(["-n", namespace])
    output, returncode = run_unchecked(*command)
    if returncode == 0:
        return True
    if "(NotFound)" in output:
        return False
    raise RuntimeError(f"Could not inspect {resource}/{name}; kubectl exited with status {returncode}")
