from __future__ import annotations

import unittest

from hunterops.storage import PostgresStorage


class StorageTests(unittest.TestCase):
    def test_disabled_storage_noop(self) -> None:
        s = PostgresStorage(dsn="", enabled=False)
        s.write_findings("run", [])
        self.assertTrue(True)


if __name__ == "__main__":
    unittest.main()

