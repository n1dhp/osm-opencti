"""Unit tests for the STIX conversion — the core logic CI must protect.

These run without a live OpenCTI: ThreatConverter.threat_to_stix() is pure and
only depends on stix2 / pycti id generation.
"""

import stix2

from converter import ThreatConverter


class _DummyHelper:
    """Stand-in for OpenCTIConnectorHelper — converter only needs a logger shape."""

    class _Logger:
        def info(self, *a, **k): ...
        def error(self, *a, **k): ...

    connector_logger = _Logger()


def _converter():
    return ThreatConverter(_DummyHelper(), label="opensourcemalware")


def _sample_threat():
    return {
        "id": "abc-123",
        "package_name": "evil-pkg",
        "resource_identifier": "evil-pkg",
        "version_info": "1.0.0",
        "registry": "npm",
        "severity_level": "critical",
        "status": "verified",
        "tags": ["backdoor", "exfiltration"],
        "threat_description": "Steals env vars.",
        "payload_description": "Posts to attacker host.",
        "osv_advisory_url": "https://osv.dev/EVIL-1",
    }


def test_author_is_organization_identity():
    author = _converter().author
    assert isinstance(author, stix2.Identity)
    assert author.identity_class == "organization"


def test_threat_to_stix_produces_malware_sdo():
    objs = _converter().threat_to_stix(_sample_threat(), "npm")
    assert len(objs) == 1
    malware = objs[0]
    assert isinstance(malware, stix2.Malware)
    assert malware.name == "evil-pkg@1.0.0 (npm)"
    assert malware.is_family is False


def test_labels_include_connector_tags_and_severity():
    malware = _converter().threat_to_stix(_sample_threat(), "npm")[0]
    assert "opensourcemalware" in malware.labels
    assert "backdoor" in malware.labels
    assert "severity:critical" in malware.labels
    # No duplicate labels.
    assert len(malware.labels) == len(set(malware.labels))


def test_severity_maps_to_score():
    malware = _converter().threat_to_stix(_sample_threat(), "npm")[0]
    assert malware.x_opencti_score == 100  # critical


def test_unknown_severity_defaults_to_50():
    threat = _sample_threat()
    threat["severity_level"] = "bogus"
    malware = _converter().threat_to_stix(threat, "npm")[0]
    assert malware.x_opencti_score == 50


def test_external_references_include_source_and_osv():
    malware = _converter().threat_to_stix(_sample_threat(), "npm")[0]
    sources = {ref.source_name for ref in malware.external_references}
    assert "opensourcemalware" in sources
    assert "OSV" in sources


def test_missing_identifier_yields_no_objects():
    threat = {"severity_level": "high"}  # no package_name / resource_identifier
    assert _converter().threat_to_stix(threat, "npm") == []


def test_version_not_duplicated_when_already_in_resource():
    threat = _sample_threat()
    threat["resource_identifier"] = "evil-pkg@2.0.0"
    threat["version_info"] = "2.0.0"
    malware = _converter().threat_to_stix(threat, "npm")[0]
    # "@" already present -> version is not appended again.
    assert malware.name == "evil-pkg@2.0.0 (npm)"
