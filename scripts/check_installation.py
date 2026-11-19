"""Check a local wheel in opted-in disposable consumers, never run native artifacts."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import venv
import zipfile


def main():
    wheel = Path(sys.argv[1]).resolve(strict=True)
    uv = shutil.which('uv')
    if uv is None:
        raise RuntimeError('uv is required for this development check')
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        assert 'automation/control_runtime_root_entry.py' in names
        assert 'tools/runner_idle_notifications.py' in names
        native = [n for n in names if n.startswith('automation/native/')]
        assert len(native) == 15, native
        assert not any(n.endswith(('.so', '.o', '.pyc')) for n in names)
        assert not any('/.env' in n or '/state/' in n for n in names)
    with tempfile.TemporaryDirectory(prefix='agent-runner-consumers-') as temporary:
        root = Path(temporary)
        env = {k: v for k, v in os.environ.items() if not k.startswith(('PYTHON', 'RUNNER_'))}
        env.update(GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1')
        def run(argv, *, cwd=root, expected=0):
            result = subprocess.run([str(x) for x in argv], cwd=cwd, env=env,
                                    capture_output=True, text=True, timeout=90)
            if result.returncode != expected:
                raise AssertionError((argv, result.returncode, result.stdout, result.stderr))
            return result.stdout
        consumers = []
        for index in (1, 2):
            project = root / f'project{index}'
            project.mkdir()
            private = root / f'operator{index}'
            private.mkdir(mode=0o700)
            runner = project / '.agent-runner'
            runner.mkdir()
            environment = runner / 'venv'
            venv.EnvBuilder(with_pip=False).create(environment)
            python = environment / 'bin/python'
            cli = environment / 'bin/agent-runner'
            run([uv, 'pip', 'install', '--python', python, '--no-deps', wheel])
            # Identical second install must remain safe and usable.
            run([uv, 'pip', 'install', '--python', python, '--no-deps', wheel])
            run([python, '-I', '-c', '''import automation, tools, importlib.metadata, pathlib
assert importlib.metadata.version("agent-runner") == "0.1.0.dev0"
for module in (automation, tools):
 p=pathlib.Path(module.__file__).resolve()
 assert "site-packages" in p.parts and ".agent-runner" in p.parts, p
import automation.control_runtime_operational, tools.runner_idle_notifications
'''])
            run([cli, '--help'])
            run([python, '-I', '-m', 'automation', '--help'])
            run(['git', 'init', '-q', '--initial-branch=main', project])
            (project / '.gitignore').write_text('.agent-runner/venv/\n.agent-runner/logs/\n.agent-runner/state/\n')
            (project / 'docs').mkdir()
            (project / 'docs/prd.md').write_text('Disposable installation fixture only.\n')
            config = dict(schema_version=1, repository=f'fixture/project{index}',
                          target_branch='main', runner_host=socket.gethostname(),
                          approvers=['maintainer'], documents=['docs/prd.md'], required_checks=['unit'],
                          selection=dict(labels=['ready'], priorities=['high','normal'],max_candidates=1))
            raw = (json.dumps(config) + '\n').encode()
            (runner / 'automation.json').write_bytes(raw)
            run(['git','add','.gitignore','.agent-runner/automation.json','docs/prd.md'],cwd=project)
            run(['git','-c','core.hooksPath=/dev/null','-c','user.name=Disposable Consumer',
                 '-c','user.email=consumer@example.invalid','commit','-qm','test: configure disposable consumer'],cwd=project)
            revision = run(['git','rev-parse','HEAD'],cwd=project).strip()
            record = dict(schema_version=1,repository=config['repository'],base_revision=revision,
                          config_sha256=hashlib.sha256(raw).hexdigest(),runner_host=socket.gethostname(),
                          approvals=[],accepted_dependencies=[])
            enrollment = private / 'enrollment.json'
            enrollment.write_text(json.dumps(record))
            enrollment.chmod(0o600)
            command = [cli,'doctor','--project',project,'--enrollment',enrollment]
            report = json.loads(run(command))
            assert report['configuration_valid'] is True
            assert report['execution_enabled'] is False and report['runtime']['status']=='unavailable'
            invalid = private / 'invalid.json'
            invalid.write_text('{"schema_version":true}')
            invalid.chmod(0o600)
            run([cli,'doctor','--project',project,'--enrollment',invalid],expected=2)
            # A pinned but invalid committed configuration also fails closed.
            invalid_raw = dict(config, selection=dict(config['selection'], max_candidates=0))
            bad_bytes = json.dumps(invalid_raw).encode()
            (runner / 'automation.json').write_bytes(bad_bytes)
            run(['git','add','.agent-runner/automation.json'],cwd=project)
            run(['git','-c','core.hooksPath=/dev/null','-c','user.name=Disposable Consumer',
                 '-c','user.email=consumer@example.invalid','commit','-qm','test: pin invalid disposable configuration'],cwd=project)
            invalid_record = dict(record, base_revision=run(['git','rev-parse','HEAD'],cwd=project).strip(),
                                  config_sha256=hashlib.sha256(bad_bytes).hexdigest())
            invalid.write_text(json.dumps(invalid_record))
            run([cli,'doctor','--project',project,'--enrollment',invalid],expected=2)
            (runner / 'automation.json').write_bytes(raw)
            run(['git','add','.agent-runner/automation.json'],cwd=project)
            run(['git','-c','core.hooksPath=/dev/null','-c','user.name=Disposable Consumer',
                 '-c','user.email=consumer@example.invalid','commit','-qm','test: restore valid disposable configuration'],cwd=project)
            # Unsupported startup leaves no service/state; advisory diagnostics still work.
            run([cli,'run','--project',project,'--enrollment',enrollment],expected=2)
            assert not (runner / 'state').exists()
            assert json.loads(run(command))['configuration_valid']
            # Reinstall/update mechanics from the reviewed local wheel; no new version claimed.
            run([uv,'pip','install','--python',python,'--no-deps','--reinstall-package','agent-runner',wheel])
            assert json.loads(run(command))['configuration_valid']
            consumers.append((project,enrollment,python,cli,raw))
        for i in (0,1):
            project, enrollment, python, cli, raw = consumers[i]
            other = consumers[1-i][1]
            run([cli,'doctor','--project',project,'--enrollment',other],expected=2)
            assert (project/'.agent-runner/automation.json').read_bytes()==raw
        # Build from ONLY installed packaged native resources; artifacts are NEVER RUN.
        compiler = shutil.which('gcc-13') or shutil.which('gcc')
        if compiler is None:
            raise RuntimeError('GCC is required for installed native closure verification')
        installed = Path(run([consumers[0][2],'-I','-c',
                              'import automation; print(automation.__path__[0])']).strip()) / 'native'
        common = ['runtime_stage0_launch.c','runtime_stage0_clock.c','runtime_stage0_admission.c']
        for private, files in ((False,['runtime_stage0_validate_main.c']+common),
                               (True,['runtime_stage0_qualification_main.c','runtime_stage0_preparer.c','runtime_stage0_records.c','runtime_stage0_persistence.c']+common)):
            command = [compiler,'-std=c11','-Wall','-Wextra','-Werror','-O2']
            if private: command += ['-DRNR_STAGE0_PRIVATE_QUALIFICATION=1']
            run(command + [installed/name for name in files] + ['-o',root/('private' if private else 'validate')])
        run([compiler,'-std=c11','-Wall','-Wextra','-Werror','-O2',installed/'runtime_guardian.c','-o',root/'guardian'])
        # Uninstall one project's package; other remains functional, owner config retained.
        run([uv,'pip','uninstall','--python',consumers[0][2],'agent-runner'])
        run([consumers[0][2],'-I','-c',
             'import importlib.util; assert importlib.util.find_spec("automation") is None; assert importlib.util.find_spec("tools") is None'])
        assert consumers[0][1].exists() and (consumers[0][0]/'.agent-runner/automation.json').exists()
        assert json.loads(run([consumers[1][3],'doctor','--project',consumers[1][0],
                              '--enrollment',consumers[1][1]]))['configuration_valid']
    print(json.dumps(dict(status='PASS',wheel_sha256=hashlib.sha256(wheel.read_bytes()).hexdigest(),
                          consumers=2,native_builds=3,native_executed=False,
                          coverage=['isolated installed imports/resources','repeat install','invalid committed configuration and enrollment',
                                    'cross-project enrollment rejection','unsupported startup and advisory recovery',
                                    'same-version reviewed reinstall','uninstall retains config and other project'],
                          limitations=['No newer-version upgrade qualification','No supported service startup/stop',
                                       'No real workload or release qualification']),indent=2))


if __name__ == '__main__':
    main()
