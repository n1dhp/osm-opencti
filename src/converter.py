import stix2
from pycti import Identity, Malware

# Map the source's severity_level to OpenCTI score buckets (0-100).
_SEVERITY_SCORE = {
    "critical": 100,
    "high": 80,
    "medium": 50,
    "low": 20,
}


class ThreatConverter:
    """Converts opensourcemalware threat records into STIX 2.1 objects."""

    def __init__(self, helper, label):
        self.helper = helper
        self.label = label
        self.author = self._create_author()

    @staticmethod
    def _create_author():
        return stix2.Identity(
            id=Identity.generate_id("Open Source Malware", "organization"),
            name="Open Source Malware",
            identity_class="organization",
            description="Community-driven feed of verified malicious open source packages (opensourcemalware.com).",
        )

    def _score(self, threat):
        return _SEVERITY_SCORE.get((threat.get("severity_level") or "").lower(), 50)

    def threat_to_stix(self, threat, ecosystem):
        """Return a list of STIX objects for a single threat record.

        Produces one Malware SDO. Returns an empty list if the record can't be
        mapped (missing identifier).
        """
        resource = threat.get("resource_identifier") or threat.get("package_name")
        if not resource:
            return []

        # Build a readable, deterministic name: "<package>@<version> (<ecosystem>)".
        name = resource
        version = threat.get("version_info")
        if version and "@" not in resource:
            name = f"{resource}@{version}"
        name = f"{name} ({threat.get('registry') or ecosystem})"

        # Labels: the connector's own label, plus the source's tags and severity.
        labels = [self.label]
        labels.extend(t for t in (threat.get("tags") or []) if t)
        if threat.get("severity_level"):
            labels.append(f"severity:{threat['severity_level']}")
        # Deduplicate while preserving order.
        labels = list(dict.fromkeys(labels))

        description = self._build_description(threat)

        external_references = self._build_external_references(threat)

        malware = stix2.Malware(
            id=Malware.generate_id(name),
            name=name,
            is_family=False,
            description=description,
            labels=labels,
            created_by_ref=self.author.id,
            external_references=external_references or None,
            custom_properties={
                "x_opencti_score": self._score(threat),
                "x_opencti_labels": labels,
            },
        )
        return [malware]

    @staticmethod
    def _build_description(threat):
        parts = []
        if threat.get("threat_description"):
            parts.append(f"**Threat:** {threat['threat_description']}")
        if threat.get("payload_description"):
            parts.append(f"**Payload:** {threat['payload_description']}")
        meta = []
        for key in (
            "registry",
            "severity_level",
            "status",
            "verified_by",
            "verified_at",
        ):
            if threat.get(key):
                meta.append(f"- {key}: {threat[key]}")
        if meta:
            parts.append("**Metadata:**\n" + "\n".join(meta))
        return "\n\n".join(parts) if parts else None

    @staticmethod
    def _build_external_references(threat):
        refs = []
        package = threat.get("package_name") or threat.get("resource_identifier")
        if package:
            refs.append(
                stix2.ExternalReference(
                    source_name="opensourcemalware",
                    description=f"opensourcemalware threat record for {package}",
                    external_id=threat.get("id"),
                )
            )
        if threat.get("osv_advisory_url"):
            refs.append(
                stix2.ExternalReference(
                    source_name="OSV", url=threat["osv_advisory_url"]
                )
            )
        if threat.get("ghsa_advisory_url"):
            refs.append(
                stix2.ExternalReference(
                    source_name="GHSA", url=threat["ghsa_advisory_url"]
                )
            )
        return refs
