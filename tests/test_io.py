import tempfile
import unittest
from pathlib import Path

from smtp_audit.core import load_values


class LoadValuesTests(unittest.TestCase):
    def test_load_single_value(self) -> None:
        self.assertEqual(load_values("smtp.example.com"), ["smtp.example.com"])

    def test_load_values_from_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_path = Path(tmp_dir) / "targets.txt"
            file_path.write_text("host1\n\nhost2\n", encoding="utf-8")
            self.assertEqual(load_values(str(file_path)), ["host1", "host2"])


if __name__ == "__main__":
    unittest.main()
