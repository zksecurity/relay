import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("download", Path(__file__).with_name("beacon-download.py"))
download = importlib.util.module_from_spec(spec)
spec.loader.exec_module(download)


class DownloadTests(unittest.TestCase):
    def setUp(self):
        # macOS's default /var path is a symlink; use its physical spelling.
        tempfile.tempdir = str(Path(tempfile.gettempdir()).resolve())

    def raw(self, round_number=42, randomness="ab" * 32):
        return json.dumps({"round": round_number, "randomness": randomness, "signature": "cd" * 48})

    def test_resume_keeps_first_retrieval_and_never_refetches_completed_run(self):
        with tempfile.TemporaryDirectory() as temp:
            calls = []
            def interrupted(url):
                calls.append(url)
                if "cloudflare" in url:
                    raise OSError("offline")
                return self.raw()
            with self.assertRaises(OSError):
                download.collect(temp, 42, interrupted)
            before = (Path(temp) / "protocol-labs.retrieval.json").read_bytes()
            calls.clear()
            download.collect(temp, 42, lambda url: calls.append(url) or self.raw())
            self.assertEqual(len(calls), 1)
            self.assertIn("cloudflare", calls[0])
            self.assertEqual(before, (Path(temp) / "protocol-labs.retrieval.json").read_bytes())
            download.collect(temp, 42, lambda _: self.fail("completed run refetched"))
            rows = (Path(temp) / "relays.tsv").read_text().splitlines()
            self.assertEqual(len(rows), 3)
            self.assertEqual({row.split("\t")[1] for row in rows[1:]}, {"cloudflare", "protocol-labs"})

    def test_wrong_round_and_disagreement_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                download.collect(temp, 42, lambda _: self.raw(43))
            with self.assertRaises(ValueError):
                download.collect(temp, 42, lambda url: self.raw(randomness=("ab" if "cloudflare" in url else "ef") * 32))
            self.assertFalse((Path(temp) / "relays.tsv").exists())

    def test_changed_or_symlinked_output_is_not_overwritten(self):
        for symlink in (False, True):
            with tempfile.TemporaryDirectory() as temp:
                target = Path(temp) / "protocol-labs.json"
                if symlink:
                    target.symlink_to("missing")
                else:
                    target.write_text("retained conflicting evidence")
                with self.assertRaises((ValueError, OSError)):
                    download.collect(temp, 42, lambda _: self.raw())
                self.assertFalse((Path(temp) / "relays.tsv").exists())

    def test_other_round_cannot_reuse_checkpoint(self):
        with tempfile.TemporaryDirectory() as temp:
            download.collect(temp, 42, lambda _: self.raw())
            with self.assertRaises(ValueError):
                download.collect(temp, 43, lambda _: self.fail("wrong-round checkpoint reused"))


if __name__ == "__main__":
    unittest.main()
