"""Finite virtual kernel for the complete frozen source path, no host trial."""
from concurrent.futures import Future
import os
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from automation import control_runtime_frozen as f
from automation.control_runtime_docker_recipe import create
from tests import test_automation_runtime_frozen_integration as integration
from tests import test_automation_runtime_frozen_delivery as security
_REAL_STAT=os.stat


def info(device,inode,mode,size=0):
    return SimpleNamespace(st_dev=device,st_ino=inode,st_mode=mode,st_uid=0,st_gid=0,
                           st_nlink=1,st_size=size,st_mtime_ns=1,st_ctime_ns=1)


class Entries:
    def __init__(self,kernel,names):
        self.kernel=kernel;self.names=iter(names);self.closed=False
    def __iter__(self):return self
    def __next__(self):return SimpleNamespace(name=next(self.names),is_dir=lambda **kw:False)
    def close(self):
        if self.closed:raise AssertionError('iterator closed twice')
        self.closed=True;self.kernel.iterators.remove(self)


class Kernel:
    def __init__(self,receiver):
        self.r=receiver;self.frozen=False;self.table={};self.next=1000
        self.opened=[];self.closed=[];self.iterators=[];self.peak=0;self.allocations=0
        self.fail_allocation=None;self.fail_close=None;self.log=[];self.task_listings=[]
        self.table_queries=0;self.fail_table_query=None
        self.allocation_log=[]
        self.asset_data={target:dict(receiver._bootstrap_context.files).get(name,b'X') for target,name in f._DESTINATIONS.items()}
        self.targets=tuple(sorted(self.asset_data));self.dev=os.makedev(253,3)
        self.anchor=receiver._pending[0].policy.clock_anchor
        self.records=security.FrozenTaskSecurityTests()
        for fd,node in ((100,('procroot',)),(101,('own',)),(20,('ancestor',))):self.table[fd]=(node,f._DIRECTORY)
        proc=receiver._guard._baseline._proc
        proc._proc=100;proc._dirs={'own':(os.getpid(),101,())};proc._proc_mount=1
        proc._proc_identity=f._object(self.metadata(('procroot',)));proc.check=Mock()
        proc._namespaces={name:(-1,f._object(self.nsinfo(name,host=True))) for name in f._NAMESPACE_TYPES}
        assets=receiver._guard._generation[0];assets._members={}
        for index,target in enumerate(self.targets):
            fd=200+index;node=('asset',target)
            self.table[fd]=(node,f._FLAGS)
            assets._members[f._DESTINATIONS[target]]=(fd,f._identity(self.metadata(node)))
        fs=receiver._guard._recovery._fs
        fs.targetfd=20;fs.rootfd=21;fs.target=receiver._guard.prepared.target
        fs.verify=Mock();fs._read=Mock(return_value=b'0\n')
        receiver._guard._recovery._remaining=Mock()
        receiver._guard._check_store_lifetime=Mock(return_value=(1,1))
        receiver._fence=Mock(side_effect=lambda:self.log.append('contain'))
        receiver._ticket=receiver._pending[0].ticket;receiver._run_id='run';receiver._epoch='epoch'
        future=Future();future.set_result(receiver._start_result)
        receiver._store.submit=Mock(return_value=future)
        receiver._channel.send=Mock()

    def nsinfo(self,name,*,host=False):
        inode=list(f._NAMESPACE_TYPES).index(name)+1
        if not host and name not in ('user','time'):inode+=100
        return info(44,inode,stat.S_IFREG|0o444)

    def pid(self,role):return 11 if role=='guardian' else 12
    def role(self,pid):return 'guardian' if pid==11 else 'app'
    def pipe_inode(self,role,n):
        return {0:301,1:302,2:303,5:401,6:402,8:403}[n] if role=='guardian' else {0:401,1:402,2:403}[n]
    def target_info(self,role,n):
        return info(66,99,0o600) if role=='guardian' and n==3 else info(55,self.pipe_inode(role,n),stat.S_IFIFO|0o600)

    def metadata(self,node):
        kind=node[0]
        if kind in ('procroot','own','process','taskroot','task','fddir'):
            inode={'procroot':1,'own':2}.get(kind,100+(node[1] if len(node)>1 else 0))
            return info(11,inode,stat.S_IFDIR|0o555)
        if kind in ('ancestor','scope'):return info(17,19 if kind=='ancestor' else 25,stat.S_IFDIR|0o755)
        if kind=='namespace':return self.nsinfo(node[1])
        if kind=='root':return info(33,50,stat.S_IFDIR|0o755)
        if kind=='asset':
            index=self.targets.index(node[1]);mode=0o555 if node[1] in ('/rnr/guardian','/rnr/codex') else 0o444
            return info(self.dev,500+index,stat.S_IFREG|mode,len(self.asset_data[node[1]]))
        if kind=='pidfd':return info(77,900+node[1],stat.S_IFREG|0o700)
        if kind=='target':return self.target_info(node[1],node[2])
        if kind=='record':return info(17 if node[1]=='cgroup' else 11,700,stat.S_IFREG|0o444)
        raise AssertionError(node)

    def measure(self):
        active=len(self.opened)-len(self.closed)+len(self.iterators)
        self.peak=max(self.peak,active)
        if active>23:raise AssertionError('virtual descriptor peak exceeded23')

    def new(self,node,flags):
        self.allocations+=1
        if self.allocations==self.fail_allocation:
            self.log.append('allocation-failed');raise OSError('injected allocation failure')
        fd=self.next;self.next+=1;self.table[fd]=(node,flags);self.opened.append(fd)
        self.allocation_log.append((self.allocations,fd,node));self.measure();return fd

    def resolve(self,base,path):
        node=self.table[base][0];kind=node[0]
        if kind=='procroot':return ('process',int(path))
        if kind=='ancestor':return ('scope',)
        if kind=='scope':return ('record','cgroup',path)
        if kind=='own':return ('record','own',path)
        if kind=='taskroot':return ('task',int(path))
        if kind in ('process','task'):
            pid=node[1]
            if path=='task':return ('taskroot',pid)
            if path.startswith('task/'):
                _,tid,tail=path.split('/',2);return self.resolve_node(('task',int(tid)),tail)
            return self.resolve_node(('task',pid),path)
        raise AssertionError((node,path))

    def resolve_node(self,node,path):
        pid=node[1];role=self.role(pid)
        if path.startswith('ns/'):
            name=path[3:];return ('namespace',f._CHILDREN.get(name,name))
        if path in ('root','cwd'):return ('root',)
        if path=='exe':return ('asset','/rnr/'+('guardian' if pid==11 else 'codex'))
        if path=='fd':return ('fddir',pid)
        if path.startswith('fd/'):return ('target',role,int(path[3:]))
        return ('record',pid,path)

    def open(self,path,flags,*,dir_fd):return self.new(self.resolve(dir_fd,path),flags)
    def beneath(self,root,path,flags):
        if self.table[root][0]!=('root',):raise AssertionError('wrong taskroot')
        target='/'+path.decode()
        if target not in f._DESTINATIONS:raise AssertionError('unexpected config target')
        return self.new(('asset',target),flags)
    def close(self,fd):
        if fd not in self.opened or fd in self.closed:raise AssertionError('borrowed or repeated numeric close')
        self.closed.append(fd);self.log.append(('close',fd))
        if self.fail_close=='all' or fd==self.fail_close:raise OSError('injected close uncertainty')
    def fstat(self,fd):return self.metadata(self.table[fd][0])
    def stat(self,path,*,dir_fd=None,follow_symlinks=True):
        if dir_fd is None:return _REAL_STAT(path,follow_symlinks=follow_symlinks)
        return self.metadata(self.resolve(dir_fd,path))
    def mount(self,fd):
        node=self.table[fd][0];kind=node[0]
        if kind=='asset':return 100+self.targets.index(node[1])
        if kind in ('scope','ancestor') or kind=='record' and node[1]=='cgroup':return 23
        if kind=='pidfd':return 50
        if kind=='target':return 51
        if kind=='namespace':return 52
        if kind=='root':return 40
        return 1
    def filesystem(self,fd):
        node=self.table[fd][0];kind=node[0]
        if kind=='asset':return 0x73717368
        if kind in ('ancestor','scope') or kind=='record' and node[1]=='cgroup':return 0x63677270
        if kind=='namespace':return 0x6e736673
        if kind=='pidfd':return 0x50494446
        if kind=='target':return 0x09041934 if node[1]=='guardian' and node[2]==3 else 0x50495045
        return 0x9fa0
    def ioctl(self,fd,command):return f._NAMESPACE_TYPES[self.table[fd][0][1]]
    def shared_table(self,leader,tid):
        # This finite model has one task per process. Never query live host
        # PIDs using the model's synthetic11/12 identifiers.
        if leader not in (11,12) or tid!=leader:raise AssertionError('unsupported modeled task table')
        self.table_queries+=1
        if self.table_queries==self.fail_table_query:
            self.log.append('table-query-failed');raise PermissionError('modeled KCMP denial')
    def epoll_target(self,*args):
        raise AssertionError('this virtual profile has no epoll descriptor')
    def readlink(self,path,*,dir_fd):
        node=self.resolve(dir_fd,path)
        if node[0]!='target':raise AssertionError(node)
        return 'anon_inode:[timerfd]' if node[1:] == ('guardian',3) else 'pipe:[%s]'%self.metadata(node).st_ino
    def scandir(self,base):
        node=self.table[base][0]
        if node[0]=='scope':names=('cgroup.type','cgroup.freeze','cgroup.events','cgroup.procs','cgroup.threads')
        elif node[0]=='taskroot':names=(str(node[1]),);self.task_listings.append(node[1])
        elif node[0]=='fddir':names=tuple(str(n) for n in ((0,1,2,3,5,6,8) if node[1]==11 else (0,1,2)))
        else:raise AssertionError(node)
        self.allocations+=1
        if self.allocations==self.fail_allocation:raise OSError('injected iterator allocation failure')
        result=Entries(self,names);self.iterators.append(result);self.measure();return result
    def write(self,fd,data):
        if self.table[fd][0]!=('record','cgroup','cgroup.freeze'):raise AssertionError('not exact descendant freeze')
        self.log.append(('write',data))
        self.frozen=data==b'1';return 1
    def pread(self,fd,size,offset):
        node=self.table[fd][0]
        raw=self.asset_data[node[1]] if node[0]=='asset' else self.record(node)
        return raw[offset:offset+size]
    def record(self,node):
        kind,who,path=node
        if who=='cgroup':return {'cgroup.type':b'domain\n','cgroup.freeze':b'1\n' if self.frozen else b'0\n',
            'cgroup.events':b'populated 1\nfrozen '+(b'1\n' if self.frozen else b'0\n'),
            'cgroup.procs':b'11\n12\n','cgroup.threads':b'11\n12\n'}[path]
        if who=='own':
            target=int(path.split('/')[1]);held,flags=self.table[target];metadata=self.metadata(held)
            raw=f'pos:\t0\nflags:\t0{flags:o}\nmnt_id:\t{self.mount(target)}\nino:\t{metadata.st_ino}\n'.encode()
            if held[0]=='pidfd':raw+=f'Pid:\t{held[1]}\nNSpid:\t{held[1]}\n'.encode()
            return raw
        pid=who;role=self.role(pid)
        st,status=self.records.records(tid=pid,pid=pid,inner=1 if pid==11 else 2,ppid=1 if pid==11 else 11)
        if path=='stat':return st
        if path=='status':return status
        if path=='children':return b'12 ' if pid==11 else b''
        if path=='cgroup':return ('0::/'+self.r._guard.prepared.target.parent+'/docker-'+'b'*64+'.scope\n').encode()
        if path=='mountinfo':
            rows=['40 1 33:0 / / ro - ext4 root ro']
            rows += [f'{100+i} 40 253:3 /{f._DESTINATIONS[t]} {t} ro - squashfs /dev/dm-3 ro' for i,t in enumerate(self.targets)]
            return ('\n'.join(rows)+'\n').encode()
        if path=='maps':
            target='/rnr/'+('guardian' if pid==11 else 'codex');ino=self.metadata(('asset',target)).st_ino
            return f'00400000-00401000 r-xp 00000000 fd:03 {ino} {target}\n00700000-00701000 r-xp 00000000 00:00 0 [vdso]\n'.encode()
        if path=='cmdline':
            if pid==11:
                c=self.r._create_context;recipe=__import__('json').loads(create(c.dispatch,__import__('json').loads(c.image_bytes)).body)
                argv=recipe['Entrypoint']+recipe['Cmd']
            else:argv=['/rnr/codex','app-server','--listen','stdio://']
            return b'\0'.join(v.encode() for v in argv)+b'\0'
        if path=='environ':return b'LANG=C.UTF-8\0' if pid==11 else b'HOME=/rnr/home\0CODEX_HOME=/rnr/home\0LANG=C.UTF-8\0'
        if path.startswith('fdinfo/'):
            n=int(path[7:]);info=self.target_info(role,n)
            flags={0:os.O_NONBLOCK,1:os.O_WRONLY|os.O_NONBLOCK,2:os.O_WRONLY,3:os.O_RDWR|os.O_NONBLOCK|os.O_CLOEXEC,
                5:os.O_WRONLY|os.O_NONBLOCK|os.O_CLOEXEC,6:os.O_NONBLOCK|os.O_CLOEXEC,8:os.O_NONBLOCK|os.O_CLOEXEC}[n] if pid==11 else (0 if n==0 else 1)
            raw=f'pos:\t0\nflags:\t0{flags:o}\nmnt_id:\t51\nino:\t{info.st_ino}\n'.encode()
            if pid==11 and n==3:
                r=self.anchor.deadline_boottime_ns-1
                raw+=f'clockid: 7\nticks: 0\nsettime flags: 01\nit_value: ({r//10**9}, {r%10**9})\nit_interval: (0, 0)\n'.encode()
            return raw
        raise AssertionError(node)

    def install(self,test):
        for name,method in (('open',self.open),('close',self.close),('fstat',self.fstat),('stat',self.stat),
                            ('pread',self.pread),('scandir',self.scandir),('write',self.write),('readlink',self.readlink)):
            test.enterContext(patch.object(f.os,name,side_effect=method))
        test.enterContext(patch.object(f.os,'get_inheritable',return_value=False))
        test.enterContext(patch.object(f.os,'fstatvfs',return_value=SimpleNamespace(f_flag=os.ST_RDONLY)))
        test.enterContext(patch.object(f.os,'pidfd_open',side_effect=lambda pid,flags:self.new(('pidfd',pid),os.O_RDWR|os.O_CLOEXEC)))
        test.enterContext(patch.object(f,'filesystem_type',side_effect=self.filesystem))
        test.enterContext(patch.object(f,'mount_id',side_effect=self.mount))
        test.enterContext(patch.object(f,'_beneath',side_effect=self.beneath))
        test.enterContext(patch.object(f,'_same_fd_table',side_effect=self.shared_table))
        test.enterContext(patch.object(f,'_epoll_target_is_current',side_effect=self.epoll_target))
        test.enterContext(patch.object(f.fcntl,'ioctl',side_effect=self.ioctl))
        test.enterContext(patch.object(f.select,'poll',return_value=SimpleNamespace(register=Mock(),poll=Mock(return_value=[]))))


class CompleteFrozenModelTests(unittest.TestCase):
    def isolated(self):
        case=unittest.TestCase()
        fixture=integration.FrozenContextIntegrationTests();fixture.setUp();case.addCleanup(fixture.doCleanups)
        r=fixture.complete_bootstrap();kernel=Kernel(r);kernel.install(case)
        return case,r,kernel

    def fixture(self):
        fixture=integration.FrozenContextIntegrationTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        r=fixture.complete_bootstrap();kernel=Kernel(r);kernel.install(self)
        return r,kernel

    def test_full_original_capture_delivery_release_and_runtime_use_only_23_new_slots(self):
        r,k=self.fixture();owner=r._capture_frozen()
        self.assertEqual(owner._phase,'FROZEN_ACQUIRED');self.assertTrue(k.frozen)
        self.assertEqual(k.task_listings,[11,12,11,12]);self.assertEqual(sum(v is not None for v in owner._slots),21)
        self.assertLessEqual(k.peak,23);self.assertGreater(k.peak,21)
        pending=r._pending;r._deliver_retained_start();r._release_frozen()
        self.assertEqual(owner._phase,'RELEASED');self.assertFalse(k.frozen);self.assertIs(r._pending,pending)
        owner._check_runtime()
        owner._abort(ValueError('terminal modeled cleanup'))
        self.assertEqual(len(k.opened),len(k.closed));self.assertFalse(k.iterators)
        self.assertEqual(len(set(k.closed)),len(k.closed))

    def test_kernel_table_denial_contains_before_drain_without_release(self):
        # First/last checks of reference acquisition and both full profiles.
        for query in range(1,13):
            with self.subTest(query=query):
                case,r,k=self.isolated();k.fail_table_query=query
                try:
                    with self.assertRaises(PermissionError):r._capture_frozen()
                    self.assertEqual(k.log[k.log.index('table-query-failed')+1],'contain')
                    self.assertEqual(r._frozen_lifecycle._phase,'FENCED')
                    self.assertNotIn(('write',b'0'),k.log)
                    self.assertEqual(len(k.opened),len(k.closed));self.assertFalse(k.iterators)
                    self.assertLessEqual(k.peak,23)
                finally:case.doCleanups()

    def test_each_persistent_acquisition_and_distinct_temporary_record_family_failure_contains_before_drain(self):
        case,r,k=self.isolated()
        try:
            owner=r._capture_frozen();persistent=set(v for v in owner._slots if v is not None)
            selected={index for index,fd,node in k.allocation_log if fd in persistent}
            families={}
            for index,fd,node in k.allocation_log:
                # One genuine open failure per distinct proc record/path/role
                # family, plus all21 retained acquisition sites, not every
                # repeated syscall or every kernel failure mode.
                families.setdefault(node,index)
            selected.update(families.values())
            owner._abort(ValueError('modeled baseline cleanup'))
        finally:case.doCleanups()
        self.assertGreaterEqual(len(selected),21)
        for index in sorted(selected):
            with self.subTest(allocation=index):
                case,r,k=self.isolated();k.fail_allocation=index
                try:
                    with self.assertRaises(OSError):r._capture_frozen()
                    owner=r._frozen_lifecycle
                    self.assertEqual(owner._phase,'FENCED');self.assertLessEqual(k.peak,23)
                    after=k.log[k.log.index('allocation-failed')+1:]
                    self.assertTrue(after);self.assertEqual(after[0],'contain')
                    self.assertEqual(len(k.opened),len(k.closed));self.assertFalse(k.iterators)
                    self.assertEqual(len(k.closed),len(set(k.closed)))
                    self.assertNotIn(('write',b'0'),k.log)
                finally:case.doCleanups()

    def test_every_retained_registration_postcheck_failure_keeps_new_fd_until_containment(self):
        case,r,k=self.isolated()
        try:
            owner=r._capture_frozen();persistent=set(v for v in owner._slots if v is not None)
            selected=[index for index,fd,node in k.allocation_log if fd in persistent]
            owner._abort(ValueError('modeled baseline cleanup'))
        finally:case.doCleanups()
        self.assertEqual(len(selected),21)
        for index in selected:
            with self.subTest(registration=index):
                case,r,k=self.isolated();clock=r._bootstrap_clock.side_effect
                def check():
                    owner=r._frozen_lifecycle
                    if k.allocations==index and k.opened and k.opened[-1] in owner._slots:
                        k.log.append('registered-postcheck-failed');raise TimeoutError('registration postcheck')
                    return clock()
                r._bootstrap_clock.side_effect=check
                try:
                    with self.assertRaises(TimeoutError):r._capture_frozen()
                    after=k.log[k.log.index('registered-postcheck-failed')+1:]
                    self.assertEqual(after[0],'contain')
                    self.assertEqual(len(k.opened),len(k.closed));self.assertFalse(k.iterators)
                    self.assertLessEqual(k.peak,23)
                finally:case.doCleanups()

    def test_release_write_unknown_preserves_historical_receipt_and_never_retries(self):
        r,k=self.fixture();owner=r._capture_frozen();receipt=r._start_result;r._deliver_retained_start()
        write=k.write
        def uncertain(fd,data):
            if data==b'0':k.log.append(('unknown-release',data));raise InterruptedError('unknown release')
            return write(fd,data)
        with patch.object(f.os,'write',side_effect=uncertain):
            with self.assertRaises(InterruptedError):r._release_frozen()
            with self.assertRaises(ValueError):owner._release()
        self.assertEqual(k.log.count(('unknown-release',b'0')),1)
        self.assertIs(r._start_result,receipt);self.assertTrue(k.frozen)
        self.assertEqual(owner._phase,'FENCED');self.assertIsInstance(owner._release_outcome.error,InterruptedError)
        self.assertEqual(len(k.opened),len(k.closed));self.assertFalse(k.iterators)

    def test_all_real_retained_close_errors_are_recorded_after_containment_without_retry(self):
        r,k=self.fixture();owner=r._capture_frozen();retained=set(v for v in owner._slots if v is not None)
        k.fail_close='all';k.log=[];owner._abort(ValueError('original failure'))
        self.assertEqual(k.log[0],'contain');self.assertEqual(len(owner.cleanup_errors),21)
        self.assertTrue(retained<=set(k.closed));before=len(k.closed);owner._close()
        self.assertEqual(before,len(k.closed));self.assertEqual(len(set(k.closed)),len(k.closed))
