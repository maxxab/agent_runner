"""Offline project source layout selection from caller-supplied bytes."""
import dataclasses
import hashlib
import os
import subprocess
import unittest
from unittest.mock import patch

from automation import control_runtime_project_layout as layout


def source(path, text):
    return layout.ProjectSource(path, text.encode("utf-8"))


def fixture_sources():
    return (
        source("automation/__init__.py", ""),
        source("automation/control_runtime_handoff.py", """
from . import control_store
from automation.control_api import make_request
if False:
    from . import control_extra
"""),
        source("automation/control_store.py", "from .control_helper import VALUE\n"),
        source("automation/control_api.py", "import json\ndef make_request(): return json.loads('{}')\n"),
        source("automation/control_extra.py", "VALUE = 1\n"),
        source("automation/control_helper.py", "VALUE = 1\n"),
        source("automation/control_unused.py", "this is intentionally not parsed !!!\n"),
    )


class ProjectLayoutTests(unittest.TestCase):
    def test_implicit_package_initializer_and_its_dependencies_are_selected(self):
        sources = (
            source("automation/__init__.py", "from . import control_helper\nimport json\nraise AssertionError('must never execute')\n"),
            source("automation/control_helper.py", "import automation.control_runtime_handoff\n"),
            source("automation/control_runtime_handoff.py", ""),
        )
        result = layout.select_project_layout(sources)
        self.assertEqual({item.module for item in result.files}, {
            "automation", "automation.control_helper", layout.ENTRY_MODULE,
        })
        self.assertEqual(result.external_import_roots, ("json",))

    def test_initializer_is_validated_even_when_entry_has_no_imports(self):
        for text in ("from . import missing\n", "def invalid(:\n", "__import__('hidden')\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                layout.select_project_layout((
                    source("automation/__init__.py", text),
                    source("automation/control_runtime_handoff.py", ""),
                ))

    def test_order_is_by_target_path_even_for_uppercase_modules(self):
        result = layout.select_project_layout((
            source("automation/__init__.py", ""),
            source("automation/A.py", ""),
            source("automation/control_runtime_handoff.py", "from . import A\n"),
        ))
        self.assertEqual([item.target for item in result.files], [
            "/rnr/project/automation/A.py",
            "/rnr/project/automation/__init__.py",
            "/rnr/project/automation/control_runtime_handoff.py",
        ])

    def test_maps_fixed_entry_import_closure_to_sorted_project_targets(self):
        selected = layout.select_project_layout(fixture_sources())
        by_source = {item.source: item for item in selected.files}

        self.assertEqual(selected.entry_module, "automation.control_runtime_handoff")
        self.assertEqual(set(by_source), {
            "automation/__init__.py",
            "automation/control_api.py",
            "automation/control_extra.py",
            "automation/control_helper.py",
            "automation/control_runtime_handoff.py",
            "automation/control_store.py",
        })
        self.assertEqual(
            [item.target for item in selected.files],
            sorted(item.target for item in selected.files),
        )
        item = by_source["automation/control_api.py"]
        raw = next(x.content for x in fixture_sources() if x.path == item.source)
        self.assertEqual(item.target, "/rnr/project/automation/control_api.py")
        self.assertEqual(item.sha256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(item.size, len(raw))
        self.assertEqual(item.mode, 0o444)
        self.assertEqual(selected.external_import_roots, ("json",))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            item.target = "/tmp/other.py"

    def test_missing_project_modules_and_star_imports_fail_closed(self):
        base = (
            source("automation/__init__.py", ""),
            source("automation/control_runtime_handoff.py", "from . import control_missing\n"),
        )
        with self.assertRaisesRegex(ValueError, "missing project module"):
            layout.select_project_layout(base)

        star = (
            source("automation/__init__.py", ""),
            source("automation/control_runtime_handoff.py", "from . import *\n"),
        )
        with self.assertRaisesRegex(ValueError, "star import"):
            layout.select_project_layout(star)

    def test_dynamic_import_and_out_of_package_imports_are_rejected(self):
        prefix = source("automation/__init__.py", "")
        for text in (
            "import importlib as loader\nloader.import_module('x')\n",
            "from importlib import import_module as load\nload('x')\n",
            "eval('1 + 1')\n",
            "import builtins\nbuiltins.eval('1 + 1')\n",
            "import builtins as b\nb.compile('pass', '<source>', 'exec')\n",
            "from builtins import exec as execute\nexecute('pass')\n",
            "from ..outside import value\n",
        ):
            sources = (prefix, source("automation/control_runtime_handoff.py", text))
            with self.subTest(text=text), self.assertRaises(ValueError):
                layout.select_project_layout(sources)

    def test_regular_expression_compile_is_not_a_dynamic_code_call(self):
        result = layout.select_project_layout((
            source("automation/__init__.py", ""),
            source("automation/control_runtime_handoff.py", "import re\npattern = re.compile('x')\n"),
        ))
        self.assertEqual(result.external_import_roots, ("re",))

    def test_bad_paths_duplicates_and_mutable_bytes_are_rejected(self):
        for path in ("/automation/control_x.py", "automation/../control_x.py",
                     "automation/sub/control_x.py", "automation/control_x.pyc"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                layout.select_project_layout((
                    source("automation/__init__.py", ""),
                    source("automation/control_runtime_handoff.py", ""),
                    source(path, "VALUE = 1\n"),
                ))

        valid = source("automation/__init__.py", "")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            layout.select_project_layout((
                valid,
                valid,
                source("automation/control_runtime_handoff.py", ""),
            ))
        with self.assertRaisesRegex(ValueError, "immutable bytes"):
            layout.select_project_layout((
                valid,
                source("automation/control_runtime_handoff.py", ""),
                layout.ProjectSource("automation/control_helper.py", bytearray(b"x")),
            ))

    def test_selector_uses_no_filesystem_or_process_operations(self):
        with patch("builtins.open", side_effect=AssertionError("open")), \
             patch.object(os, "open", side_effect=AssertionError("os.open")), \
             patch.object(os, "stat", side_effect=AssertionError("stat")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process")):
            selected = layout.select_project_layout(fixture_sources())
        self.assertEqual(selected.entry_module, layout.ENTRY_MODULE)

    def test_operational_profile_has_distinct_fixed_entry_and_lifecycle_roots(self):
        sources=(source('automation/__init__.py',''),
            source('automation/control_runtime_operational.py','from .control_helper import value\n'),
            source('automation/control_runtime_receiver.py','from . import control_views\n'),
            source('automation/control_runtime_dispatch.py',''),
            source('automation/control_runtime_consumer.py','from . import control_consumer_dependency\n'),
            source('automation/control_consumer_dependency.py',''),
            source('automation/control_helper.py','value=1\n'),source('automation/control_views.py',''),
            source('automation/control_runtime_handoff.py',''))
        with patch('builtins.open',side_effect=AssertionError('no filesystem')), \
             patch.object(subprocess,'Popen',side_effect=AssertionError('no process')):
            selected=layout.select_operational_project_layout(sources)
        self.assertEqual(selected.entry_module,'automation.control_runtime_operational')
        modules={f.module for f in selected.files}
        self.assertTrue({'automation.control_runtime_receiver','automation.control_runtime_dispatch',
            'automation.control_runtime_consumer','automation.control_consumer_dependency',
            'automation.control_views','automation.control_helper'}<=modules)
        self.assertNotIn('automation.control_runtime_handoff',modules)
        self.assertEqual(selected,layout.select_operational_project_layout(tuple(reversed(sources))))
        with self.assertRaisesRegex(ValueError,'fixed project'):
            layout.select_operational_project_layout(tuple(s for s in sources if 'receiver.py' not in s.path))
        with self.assertRaisesRegex(ValueError,'fixed project'):
            layout.select_operational_project_layout(tuple(s for s in sources if 'consumer.py' not in s.path))

    def test_entries_are_data_only_and_deterministic(self):
        first = layout.select_project_layout(fixture_sources())
        second = layout.select_project_layout(tuple(reversed(fixture_sources())))
        self.assertEqual(first, second)
        self.assertFalse(hasattr(first, "runtime_accepted"))
        self.assertFalse(hasattr(first, "startup_authorized"))

    def test_required_inputs_and_reachable_syntax_are_checked(self):
        package = source("automation/__init__.py", "")
        entry = source("automation/control_runtime_handoff.py", "")
        for sources in ([], (), (package,), (entry,), (package, object()),
                        (package, source(entry.path, "def invalid(:\n"))):
            with self.subTest(sources=sources), self.assertRaises(ValueError):
                layout.select_project_layout(sources)

    def test_count_per_file_and_total_byte_bounds_include_the_boundary(self):
        sources = (source("automation/__init__.py", "\n"),
                   source("automation/control_runtime_handoff.py", "\n\n"))
        with patch.multiple(layout, MAX_FILES=2, MAX_SOURCE_BYTES=2, MAX_TOTAL_BYTES=3):
            self.assertEqual(len(layout.select_project_layout(sources).files), 2)
            with self.assertRaisesRegex(ValueError, "tuple"):
                layout.select_project_layout(sources + (source("automation/extra.py", ""),))
        with patch.object(layout, "MAX_SOURCE_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "source byte bound"):
                layout.select_project_layout(sources)
        with patch.object(layout, "MAX_TOTAL_BYTES", 2):
            with self.assertRaisesRegex(ValueError, "aggregate bound"):
                layout.select_project_layout(sources)


if __name__ == "__main__":
    unittest.main()
