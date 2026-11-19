"""Closed proc identity profiles; no observation or readiness authority."""
import unittest
from automation import control_runtime_proc as proc


def status():
    fields = {
        'Name':'fixture', 'Umask':'0022', 'State':'S (sleeping)',
        'Tgid':'11','Ngid':'0','Pid':'11','PPid':'1','TracerPid':'0',
        'Uid':'0\t0\t0\t0','Gid':'0\t0\t0\t0','FDSize':'64','Groups':'0 ',
        'NStgid':'11','NSpid':'11','NSpgid':'11','NSsid':'11','Kthread':'0',
        'CoreDumping':'0','THP_enabled':'1','untag_mask':'0xffffffffffffffff',
        'Threads':'1','SigQ':'0/31520','NoNewPrivs':'0','Seccomp':'0','Seccomp_filters':'0',
        'Speculation_Store_Bypass':'thread vulnerable', 'SpeculationIndirectBranch':'conditional enabled',
        'Cpus_allowed':'ff','Cpus_allowed_list':'0-7','Mems_allowed':'00000001','Mems_allowed_list':'0',
        'voluntary_ctxt_switches':'0','nonvoluntary_ctxt_switches':'0',
    }
    for key in ('VmPeak','VmSize','VmLck','VmPin','VmHWM','VmRSS','RssAnon','RssFile',
                'RssShmem','VmData','VmStk','VmExe','VmLib','VmPTE','VmSwap','HugetlbPages'):
        fields[key]='    4 kB'
    for key in ('SigPnd','ShdPnd','SigBlk','SigIgn','SigCgt','CapInh','CapPrm','CapEff','CapBnd','CapAmb'):
        fields[key]='0000000000000000'
    return ''.join(k+':\t'+v+'\n' for k,v in fields.items()).encode()


class IdentityProfileTests(unittest.TestCase):
    def parse_status(self,raw):
        parse=getattr(proc,'_parse_status',None)
        self.assertTrue(callable(parse),'full supported status parser missing')
        return parse(raw)

    def parse_pidfd(self,raw):
        parse=getattr(proc,'_parse_pidfdinfo',None)
        self.assertTrue(callable(parse),'closed pidfd fdinfo parser missing')
        return parse(raw)

    def test_status_retains_identity_credentials_and_namespace_vectors(self):
        value=self.parse_status(status())
        self.assertEqual((value.pid,value.tgid,value.ppid,value.nspid),(11,11,1,(11,)))
        self.assertEqual(value.uid,(0,0,0,0));self.assertEqual(value.gid,(0,0,0,0))
        self.assertEqual(value.state,b'S');self.assertEqual(value.threads,1)
        nested=self.parse_status(status().replace(b'NSpid:\t11\n',b'NSpid:\t11\t1\n'))
        self.assertEqual(nested.nspid,(11,1)) # data; same-view consumer must reject nesting

    def test_status_rejects_duplicate_unknown_missing_truncated_and_bad_grammars(self):
        original=status()
        bad=[original+b'Pid:\t11\n',original+b'Future:\t1\n',original.replace(b'Pid:\t11\n',b''),
             original[:-1],original+b'\x00',original.replace(b'Pid:\t11\n',b'Pid:\t011\n'),
             original.replace(b'Uid:\t0\t0\t0\t0',b'Uid:\t0\t0\t0'),
             original.replace(b'Seccomp:\t0',b'Seccomp:\t3'),
             original.replace(b'CapEff:\t0000000000000000',b'CapEff:\t000000000000000g'),
             original.replace(b'VmRSS:\t    4 kB',b'VmRSS:\t4 MB'),
             original.replace(b'NSpid:\t11',b'NSpid:\t11\t0'),
             original.replace(b'Cpus_allowed_list:\t0-7',b'Cpus_allowed_list:\t7-0')]
        for raw in bad:
            with self.subTest(raw=raw[-100:]),self.assertRaises(ValueError):self.parse_status(raw)

    def test_status_dead_state_is_data_not_liveness(self):
        value=self.parse_status(status().replace(b'S (sleeping)',b'Z (zombie)'))
        self.assertEqual(value.state,b'Z')

    def test_pidfd_full_layout_and_nested_vector(self):
        value=self.parse_pidfd(b'pos:\t0\nflags:\t02000002\nmnt_id:\t5\nino:\t42\nPid:\t11\nNSpid:\t11\t1\n')
        self.assertEqual((value.pid,value.nspid),(11,(11,1)))
        self.assertEqual(value.inode,42)

    def test_pidfd_rejects_forged_or_ambiguous_records(self):
        good=b'pos:\t0\nflags:\t02000002\nmnt_id:\t5\nino:\t42\nPid:\t11\nNSpid:\t11\n'
        bad=[good+b'Pid:\t11\n',good+b'lock:\t1\n',good.replace(b'ino:\t42\n',b''),good[:-1],
             good.replace(b'NSpid:\t11',b'NSpid:\t12'),good.replace(b'Pid:\t11',b'Pid:\t-1'),
             good.replace(b'pos:\t0',b'pos:\t1'),good.replace(b'flags:\t02000002',b'flags:\t02000008')]
        for raw in bad:
            with self.subTest(raw=raw),self.assertRaises(ValueError):self.parse_pidfd(raw)

if __name__=='__main__':unittest.main()
