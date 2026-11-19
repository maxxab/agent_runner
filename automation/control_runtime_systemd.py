"""Inert closed systemd255 manager arguments/readback, no process or bus calls.

Future separately authorized sealed provisioner must verify held cgroup2 root,
original clock and ALREADY enabled controllers before the single start attempt;
consume attempt before send, never retry a lost ACK, and retain UNKNOWN target.
These helpers do not authenticate a manager or prove physical unit retention.
"""
import json
import re
from .control_runtime_containment import validate_slice_recipe

_SERVICE='org.freedesktop.systemd1'
_ROOT='/org/freedesktop/systemd1'
_UNIT='org.freedesktop.systemd1.Unit'
_SLICE='org.freedesktop.systemd1.Slice'
_UNIT_PROPERTIES={'StopWhenUnneeded','CollectMode','RefuseManualStop','IgnoreOnIsolate',
    'AllowIsolate','DefaultDependencies','ActiveState','SubState','LoadState','Transient','Job'}
_EXTRA={'ActiveState':'s','SubState':'s','LoadState':'s','Transient':'b','ControlGroup':'s','Job':'(uo)'}


def start_arguments(recipe):
    recipe=validate_slice_recipe(recipe)
    args=['call',_SERVICE,_ROOT,'org.freedesktop.systemd1.Manager','StartTransientUnit',
          'ssa(sv)a(sa(sv))',recipe.name,'fail',str(len(recipe.properties))]
    for name,kind,value in recipe.properties:
        args.extend((name,kind,str(value).lower() if type(value) is bool else str(value)))
    return tuple(args+['0'])  # no auxiliary units


def property_types(recipe):
    recipe=validate_slice_recipe(recipe)
    return {name:kind for name,kind,_ in recipe.properties}|_EXTRA


def read_arguments(recipe):
    recipe=validate_slice_recipe(recipe)
    path=_ROOT+'/unit/'+recipe.name.replace('.','_2e')
    names=property_types(recipe)
    return tuple(tuple(['get-property',_SERVICE,path,interface]+sorted(
        name for name in names if (name in _UNIT_PROPERTIES)==is_unit))
        for interface,is_unit in ((_UNIT,True),(_SLICE,False)))


def parse_value(kind,line):
    """One busctl255 terse typed property line; no coercion or excess fields."""
    if type(line) is not str or len(line)>4096 or '\n' in line or '\r' in line:
        raise ValueError('bounded single typed property required')
    prefix=kind+' '
    if not line.startswith(prefix):raise ValueError('manager property type differs')
    value=line[len(prefix):]
    if kind=='b' and value in ('true','false'):return value=='true'
    if kind=='t' and re.fullmatch(r'0|[1-9][0-9]{0,19}',value):
        number=int(value)
        if number<2**64:return number
    if kind=='s':
        parsed=json.loads(value)
        if type(parsed) is str and len(parsed)<=256:return parsed
    if kind=='(uo)' and value=='0 "/"':return [0,'/']
    raise ValueError('closed canonical manager property required')


def project_readback(recipe,unit_output,slice_output):
    args=read_arguments(recipe);types=property_types(recipe);result={}
    for request,output in zip(args,(unit_output,slice_output)):
        if type(output) is not bytes or len(output)>16384:raise ValueError('bounded readback required')
        lines=output.decode('utf-8').splitlines();names=request[4:]
        if len(lines)!=len(names):raise ValueError('exact readback inventory required')
        for name,line in zip(names,lines):result[name]=parse_value(types[name],line)
    return result


def verify_controllers(controllers,enabled,kind):
    """No write/enablement fallback; outer root mount must be authenticated."""
    def tokens(data):
        if type(data) is not bytes or len(data)>4096:raise ValueError('bounded controller readback required')
        parts=data.split()
        if len(set(parts))!=len(parts) or any(re.fullmatch(rb'[a-z][a-z0-9_]*',p) is None for p in parts):
            raise ValueError('closed controller metadata required')
        return set(parts)
    required={b'cpu',b'memory',b'pids'}
    if type(kind) is not bytes or kind!=b'domain\n' or not required<=tokens(controllers) or not required<=tokens(enabled):
        raise ValueError('required domain controllers must already be enabled')
