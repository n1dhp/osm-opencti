import sys
from datetime import UTC, datetime

import stix2
from pycti import OpenCTIConnectorHelper

from client import OpenSourceMalwareClient
from config_loader import ConfigConnector
from converter import ThreatConverter


class OpenSourceMalwareConnector:
    """External-import connector ingesting verified malicious packages from
    opensourcemalware.com as STIX Malware objects, tagged with a configurable label.
    """

    def __init__(self):
        self.helper = OpenCTIConnectorHelper({})
        self.config = ConfigConnector()
        self.client = OpenSourceMalwareClient(
            self.helper, self.config.api_base_url, self.config.api_token
        )
        self.converter = ThreatConverter(self.helper, self.config.label)

    def _collect(self):
        """Fetch and convert threats across all configured ecosystems."""
        stix_objects = [self.converter.author]
        for ecosystem in self.config.ecosystems:
            threats = self.client.query_latest(ecosystem)
            self.helper.connector_logger.info(
                "Fetched threats",
                {"ecosystem": ecosystem, "count": len(threats)},
            )
            for threat in threats:
                if self.config.verified_only and threat.get("status") != "verified":
                    continue
                stix_objects.extend(self.converter.threat_to_stix(threat, ecosystem))
        return stix_objects

    def process_message(self):
        now = datetime.now(tz=UTC)
        friendly_name = f"Open Source Malware run @ {now.isoformat()}"
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )
        try:
            stix_objects = self._collect()
            # Only the author was collected -> nothing to send.
            if len(stix_objects) <= 1:
                self.helper.api.work.to_processed(
                    work_id, "No threats to import", in_error=False
                )
                return

            bundle = stix2.Bundle(objects=stix_objects, allow_custom=True).serialize()
            sent = self.helper.send_stix2_bundle(bundle, work_id=work_id)
            self.helper.connector_logger.info(
                "Bundle sent",
                {"objects": len(stix_objects), "bundles": len(sent)},
            )
            self.helper.api.work.to_processed(
                work_id,
                f"Imported {len(stix_objects) - 1} malicious packages",
            )
        except Exception as err:  # noqa: BLE001
            self.helper.connector_logger.error("Error during run", {"error": str(err)})
            self.helper.api.work.to_processed(work_id, str(err), in_error=True)

    def run(self):
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.helper.connect_duration_period,
        )


if __name__ == "__main__":
    try:
        OpenSourceMalwareConnector().run()
    except Exception:  # noqa: BLE001
        import traceback

        traceback.print_exc()
        sys.exit(1)
