"""Descriptor queries exercise actual local kernel ABI, without host mutation."""
import os
import tempfile
import unittest

class LinuxDescriptorTests(unittest.TestCase):
    def test_proc_magic_and_distinct_named_mount(self):
        from automation.control_runtime_linux import filesystem_type,mount_id
        descriptors=[]
        try:
            for path in ('/proc','/proc/self/status','/'):
                descriptors.append(os.open(path,os.O_RDONLY|os.O_CLOEXEC))
            self.assertEqual(filesystem_type(descriptors[0]),0x9fa0)
            self.assertEqual(filesystem_type(descriptors[1]),0x9fa0)
            self.assertEqual(mount_id(descriptors[0]),mount_id(descriptors[1]))
            self.assertNotEqual(mount_id(descriptors[0]),mount_id(descriptors[2]))
        finally:
            for fd in descriptors:os.close(fd)
    def test_invalid_descriptor_rejects_without_path_fallback(self):
        from automation.control_runtime_linux import filesystem_type,mount_id
        for query in (filesystem_type,mount_id):
            with self.assertRaises(OSError):query(2**30)

if __name__=='__main__':unittest.main()
