"""Offline runtime payload selection: no candidate files are opened."""
import dataclasses
import unittest
from unittest.mock import patch

from automation import control_runtime_payload as p

PY = "/usr/bin/python3.12"
LIB = "/usr/lib/x86_64-linux-gnu/"
STD = "/usr/lib/python3.12/"
H = "a" * 64


def f(path, mode=0o644):
    return p.Candidate(path, H, 12, mode)


class PayloadSelectionTests(unittest.TestCase):
    def select(self, files=(), aliases=(), flags=("-I", "-S", "-B")):
        return p.select_runtime_payload(tuple(files), tuple(aliases), flags)

    def test_regular_copy_alias_and_explicit_modes(self):
        lib = LIB + "libx.so.1"
        result = self.select([f(PY, 0o6755), f(lib, 0o777)],
                             [p.Alias(LIB + "libx.so", "libx.so.1", lib)])
        by_path = {x.path: x for x in result.files}
        self.assertEqual(by_path[PY].mode, 0o555)
        self.assertEqual(by_path[LIB + "libx.so"].source, lib)
        self.assertEqual(by_path[LIB + "libx.so"].sha256, H)
        self.assertEqual(by_path[lib].mode, 0o444)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.files = ()

    def test_cache_and_hook_exclusions_are_path_based(self):
        paths = [STD + "__pycache__/os.cpython-312.pyc", STD + "os.pyc",
                 STD + "old.pyo", STD + "sitecustomize.py",
                 STD + "usercustomize/__init__.py"]
        result = self.select([f(PY), *map(f, paths)],
                             [p.Alias(STD + "sitecustomize.py",
                                      "/etc/python3.12/sitecustomize.py", None)])
        self.assertEqual([x.path for x in result.files], [PY])
        self.assertEqual({x.path for x in result.exclusions}, set(paths))

    def test_external_link_cannot_be_rehabilitated_by_resolved_field(self):
        for target in ["/etc/evil", "../../../../etc/evil"]:
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.select([f(PY), f(STD + "os.py")],
                            [p.Alias(STD + "alias.py", target, STD + "os.py")])

    def test_missing_dangling_alias_and_cache_sources_rejected(self):
        for source in [STD + "missing", STD + "other-alias", STD + "os.pyc"]:
            with self.subTest(source=source), self.assertRaises(ValueError):
                self.select([f(PY), f(STD + "os.pyc")],
                            [p.Alias(STD + "alias.py", "os.py", source)])

    def test_duplicates_and_collisions(self):
        a = p.Alias(LIB + "libx.so", "libx.so.1", LIB + "libx.so.1")
        result = self.select([f(PY), f(a.source)], [a, a])
        self.assertEqual(len(result.files), 3)
        for aliases in [[a, dataclasses.replace(a, target="different")],
                        [p.Alias(PY, PY, PY)]]:
            with self.assertRaises(ValueError):
                self.select([f(PY), f(a.source)], aliases)
        with self.assertRaises(ValueError):
            self.select([f(PY), f(PY)])

    def test_only_exact_directory_aliases_are_omitted(self):
        result = self.select([f(PY)], [p.Alias("/lib", "usr/lib", None),
                                      p.Alias("/lib64", "usr/lib64", None)])
        self.assertEqual(len(result.exclusions), 2)
        with self.assertRaises(ValueError):
            self.select([f(PY)], [p.Alias("/lib", "/etc", None)])

    def test_loader_alias_keeps_executable_mode(self):
        source = LIB + "ld-linux-x86-64.so.2"
        result = self.select([f(PY), f(source)],
                            [p.Alias("/lib64/ld-linux-x86-64.so.2",
                                     "../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                                     source)])
        self.assertEqual({x.mode for x in result.files}, {0o555})

    def test_profile_required(self):
        for flags in [("-I", "-B"), ("-S",), ["-I", "-S", "-B"]]:
            with self.subTest(flags=flags), self.assertRaises(ValueError):
                self.select([f(PY)], flags=flags)

    def test_malformed_and_outside_paths_rejected(self):
        for path in ["/etc/passwd", STD + "../evil", STD + "a//b",
                     STD + "./x", STD + "x\x00", "//usr/bin/python3.12"]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.select([f(PY), f(path)])
        for changed in [dict(size=True), dict(size=2**30), dict(sha256="x"*64),
                        dict(observed_mode=-1), dict(observed_mode=True)]:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.select([dataclasses.replace(f(PY), **changed)])

    def test_file_ancestor_conflict(self):
        with self.assertRaises(ValueError):
            self.select([f(PY), f(STD + "x"), f(STD + "x/y")])

    def test_no_filesystem_or_process_operations(self):
        with patch("builtins.open", side_effect=AssertionError("open")), \
             patch("os.open", side_effect=AssertionError("os.open")), \
             patch("os.stat", side_effect=AssertionError("stat")), \
             patch("subprocess.Popen", side_effect=AssertionError("process")):
            result = self.select([f(PY), f(STD + "os.py")])
        self.assertEqual(len(result.files), 2)

    def test_missing_interpreter_and_oversized_input(self):
        with self.assertRaises(ValueError):
            self.select([f(STD + "os.py")])
        with self.assertRaises(ValueError):
            self.select([f(PY)] * 4097)

    def test_aggregate_payload_bound(self):
        large = [dataclasses.replace(f(LIB + "lib%d.so" % i),
                                     size=64 * 1024 * 1024) for i in range(4)]
        with self.assertRaises(ValueError):
            self.select([f(PY), *large])

    def test_alias_source_rejected_in_both_orders(self):
        source = LIB + "libx.so.1"
        first = p.Alias(LIB + "libx.so", "libx.so.1", source)
        second = p.Alias(source, "libz.so.1", LIB + "libz.so.1")
        for aliases in [(first, second), (second, first)]:
            with self.subTest(aliases=aliases), self.assertRaises(ValueError):
                self.select([f(PY), f(source), f(LIB + "libz.so.1")], aliases)
