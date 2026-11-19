"""Offline ELF metadata only: independent synthetic program-header fixtures."""
import dataclasses
import hashlib
import importlib
import importlib.util
import struct
import unittest

BASE = 0x400000

def fixture():
    data = bytearray(1024)
    ident = b'\x7fELF' + bytes((2, 1, 1)) + bytes(9)
    struct.pack_into('<16sHHIQQQIHHHHHH', data, 0, ident, 3, 62, 1,
                     BASE, 64, 0, 0, 64, 56, 3, 0, 0, 0)
    ph(data, 0, 1, 0, BASE, len(data), len(data), 4096)
    interp = b'/lib64/ld.so\0'
    data[240:240 + len(interp)] = interp
    ph(data, 1, 3, 240, BASE + 240, len(interp), len(interp))
    strings = b'\0liba.so\0libb.so\0$ORIGIN/lib\0/opt/lib\0'
    data[512:512 + len(strings)] = strings
    entries = ((5, BASE + 512), (10, len(strings)), (1, 1), (1, 9),
               (15, 17), (29, 29), (0, 0))
    for i, pair in enumerate(entries):
        struct.pack_into('<qQ', data, 320 + i * 16, *pair)
    ph(data, 2, 2, 320, BASE + 320, len(entries) * 16, len(entries) * 16)
    return data

def ph(data, index, kind, offset, address, size, memory, align=1):
    struct.pack_into('<IIQQQQQQ', data, 64 + index * 56,
                     kind, 4, offset, address, 0, size, memory, align)

class ElfDependencyTests(unittest.TestCase):
    def inspect(self, data):
        self.assertIsNotNone(importlib.util.find_spec('automation.control_runtime_elf'),
                             'offline ELF dependency inspector missing')
        return importlib.import_module('automation.control_runtime_elf').inspect_dependencies(data)

    def test_extracts_ordered_unresolved_names_and_frozen_result(self):
        data = bytes(fixture())
        result = self.inspect(data)
        self.assertEqual((result.file_bytes, result.sha256, result.elf_type),
                         (1024, hashlib.sha256(data).hexdigest(), 3))
        self.assertEqual(result.interpreter, '/lib64/ld.so')
        self.assertEqual(result.needed, ('liba.so', 'libb.so'))
        self.assertEqual((result.rpath, result.runpath), ('$ORIGIN/lib', '/opt/lib'))
        with self.assertRaises(dataclasses.FrozenInstanceError): result.needed = ()
        self.assertFalse(hasattr(result, 'runtime_accepted'))

    def test_static_data_has_no_inferred_loader_or_completeness(self):
        data = fixture(); struct.pack_into('<H', data, 56, 1)
        struct.pack_into('<H', data, 16, 2)
        result = self.inspect(bytes(data))
        self.assertEqual((result.elf_type, result.interpreter, result.needed,
                          result.rpath, result.runpath), (2, None, (), None, None))

    def test_rejects_mutable_truncated_and_unsupported_headers(self):
        for data in (fixture(), memoryview(fixture()), b'', bytes(fixture()[:63])):
            with self.subTest(kind=type(data).__name__), self.assertRaises(ValueError): self.inspect(data)
        for offset, fmt, value in ((4, 'B', 1), (5, 'B', 2), (6, 'B', 0),
                (7, 'B', 255), (8, 'B', 1), (9, 'B', 1), (16, 'H', 1),
                (18, 'H', 183), (20, 'I', 2), (32, 'Q', 0),
                (48, 'I', 1), (52, 'H', 0), (54, 'H', 55), (56, 'H', 129)):
            data = fixture(); struct.pack_into('<'+fmt, data, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError): self.inspect(bytes(data))
        with self.assertRaises(ValueError): self.inspect(bytes(fixture()[:200]))

    def test_conflicting_load_ranges_and_invalid_alignment_reject(self):
        for offset, address, size, memory, align in (
                (500, BASE + 500, 10, 10, 1), (500, BASE + 2048, 10, 10, 1),
                (1020, BASE + 2048, 10, 10, 1), (0, BASE, 1024, 100, 1),
                (0, BASE, 1024, 1024, 3), (0, BASE+1, 1024, 1024, 4096),
                (0, 2**64-1, 1024, 1024, 1)):
            data = fixture(); ph(data, 1, 1, offset, address, size, memory, align)
            with self.subTest(address=address,align=align), self.assertRaises(ValueError): self.inspect(bytes(data))

    def test_bad_dynamic_mapping_bounds_and_termination_reject(self):
        for offset, address, size in ((320, BASE+321,112),(320,BASE+320,111),
                (320,BASE+2000,112),(1000,BASE+1000,112),(320,BASE+320,0)):
            data=fixture();ph(data,2,2,offset,address,size,size)
            with self.subTest(offset=offset,address=address,size=size),self.assertRaises(ValueError):self.inspect(bytes(data))
        data=fixture();struct.pack_into('<qQ',data,416,1,1)
        with self.assertRaises(ValueError):self.inspect(bytes(data))
        data=fixture();struct.pack_into('<qQ',data,400,0,0);struct.pack_into('<qQ',data,416,1,1)
        with self.assertRaises(ValueError):self.inspect(bytes(data))

    def test_duplicate_singletons_and_bad_string_pointers_reject(self):
        for tag,value in ((5,BASE+512),(10,37),(15,17)):
            data=fixture();struct.pack_into('<qQ',data,400,tag,value)
            with self.subTest(tag=tag),self.assertRaises(ValueError):self.inspect(bytes(data))
        for tag,value in ((5,BASE+2000),(5,BASE+1000),(10,1048577),(10,0)):
            data=fixture();index=0 if tag==5 else 1;struct.pack_into('<qQ',data,320+16*index,tag,value)
            with self.subTest(tag=tag,value=value),self.assertRaises(ValueError):self.inspect(bytes(data))
        for value in (37,2**64-1):
            data=fixture();struct.pack_into('<qQ',data,352,1,value)
            with self.assertRaises(ValueError):self.inspect(bytes(data))
        data=fixture();data[549]=65
        with self.assertRaises(ValueError):self.inspect(bytes(data))
        data=fixture();data[513]=255
        with self.assertRaises(ValueError):self.inspect(bytes(data))

    def test_duplicate_program_headers_and_interpreter_termination_reject(self):
        data=fixture();ph(data,2,3,240,BASE+240,13,13)
        with self.assertRaises(ValueError):self.inspect(bytes(data))
        data=fixture();ph(data,1,2,320,BASE+320,112,112)
        with self.assertRaises(ValueError):self.inspect(bytes(data))
        for value in (b'relative/path',b'/bad\0path\0'):
            data=fixture();data[240:240+len(value)]=value;ph(data,1,3,240,BASE+240,len(value),len(value))
            with self.assertRaises(ValueError):self.inspect(bytes(data))

    def test_empty_search_path_and_duplicate_needed_are_raw_metadata(self):
        data=fixture();struct.pack_into('<qQ',data,368,1,1);struct.pack_into('<qQ',data,384,15,0)
        result=self.inspect(bytes(data))
        self.assertEqual(result.needed,('liba.so','liba.so'))
        self.assertEqual(result.rpath,'')

    def test_dependency_count_and_string_length_boundaries(self):
        for count in (256,257):
            data=fixture();data.extend(bytes(16384-len(data)))
            ph(data,0,1,0,BASE,len(data),len(data),4096)
            data[8192:8194]=b'a\0'
            pairs=[(5,BASE+8192),(10,2)]+[(1,0)]*count+[(0,0)]
            for i,pair in enumerate(pairs):struct.pack_into('<qQ',data,320+16*i,*pair)
            ph(data,2,2,320,BASE+320,len(pairs)*16,len(pairs)*16)
            if count==256:self.assertEqual(self.inspect(bytes(data)).needed,('a',)*256)
            else:
                with self.assertRaises(ValueError):self.inspect(bytes(data))
        for length in (4096,4097):
            data=fixture();data.extend(bytes(16384-len(data)))
            ph(data,0,1,0,BASE,len(data),len(data),4096)
            data[512:512+length+1]=b'x'*length+b'\0'
            for i,pair in enumerate(((5,BASE+512),(10,length+1),(1,0),(0,0))):
                struct.pack_into('<qQ',data,320+16*i,*pair)
            ph(data,2,2,320,BASE+320,64,64)
            if length==4096:self.assertEqual(self.inspect(bytes(data)).needed,('x'*4096,))
            else:
                with self.assertRaises(ValueError):self.inspect(bytes(data))

    def test_dynamic_entry_and_file_size_limits(self):
        for count in (4096,4097):
            data=fixture();data.extend(bytes(131072-len(data)))
            ph(data,0,1,0,BASE,len(data),len(data),4096)
            data[320:320+16*count]=bytes(16*count)
            ph(data,2,2,320,BASE+320,16*count,16*count)
            if count==4096:self.assertEqual(self.inspect(bytes(data)).needed,())
            else:
                with self.assertRaises(ValueError):self.inspect(bytes(data))
        with self.assertRaises(ValueError):self.inspect(bytes(64*1024*1024+1))

    def test_string_table_pair_and_bss_mapping_are_not_guessed(self):
        for offset in (320,336):
            data=fixture();struct.pack_into('<qQ',data,offset,99,0)
            with self.assertRaises(ValueError):self.inspect(bytes(data))
        data=fixture();ph(data,0,1,0,BASE,512,2048,4096)
        with self.assertRaises(ValueError):self.inspect(bytes(data))
        data=fixture();struct.pack_into('<qQ',data,352,99,123)
        self.assertEqual(self.inspect(bytes(data)).needed,('libb.so',))

    def test_null_union_values_are_ignored_without_new_dependencies(self):
        data=fixture();ph(data,2,2,320,BASE+320,128,128)
        struct.pack_into('<qQ',data,416,0,2**64-1)
        struct.pack_into('<qQ',data,432,0,47699)
        result=self.inspect(bytes(data))
        self.assertEqual(result.needed,('liba.so','libb.so'))
        self.assertEqual((result.rpath,result.runpath),('$ORIGIN/lib','/opt/lib'))
