import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PackagingTests(unittest.TestCase):
    def test_service_uses_documented_venv_entrypoint(self):
        unit = (ROOT / "packaging" / "ig-kmx-guardd.service").read_text()
        exec_starts = [
            line for line in unit.splitlines() if line.startswith("ExecStart=")
        ]
        self.assertEqual(
            exec_starts,
            [
                "ExecStart=/opt/ig-kmx-guardd/venv/bin/ig-kmx-guardd "
                "--config /etc/ig-kmx-guardd/config.json"
            ],
        )

    def test_example_accepts_the_orka_supervisor_peer_uid(self):
        config = json.loads((ROOT / "packaging" / "config.example.json").read_text())
        self.assertEqual(config["allowed_uids"], [0])


if __name__ == "__main__":
    unittest.main()
