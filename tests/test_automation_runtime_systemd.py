"""Exact dormant manager wire contract only; no bus or process execution."""
from dataclasses import replace
import unittest
import json
from automation import control_runtime_systemd as manager
from automation import control_runtime_containment as containment
from tests import test_automation_runtime_containment as fixtures


class ManagerTests(unittest.TestCase):
    def setUp(self):
        f=fixtures.ContainmentTests();f.setUp();self.addCleanup(f.doCleanups)
        self.recipe=containment.slice_recipe(f.target.parent,f.policy.quota)
    def test_closed_start_has_one_slice_no_auxiliary_units_and_no_shell(self):
        args=manager.start_arguments(self.recipe)
        self.assertEqual(args[:7],('call','org.freedesktop.systemd1','/org/freedesktop/systemd1',
            'org.freedesktop.systemd1.Manager','StartTransientUnit','ssa(sv)a(sa(sv))',self.recipe.name))
        self.assertEqual(args[7:9],('fail',str(len(self.recipe.properties))))
        self.assertEqual(args[-1],'0')
        self.assertNotIn('StopUnit',args);self.assertNotIn('SetUnitProperties',args)
    def test_exact_typed_projection_rejects_coercion_unknown_and_trailing_data(self):
        values={'s':'"active"','b':'true','t':'123','(uo)':'0 "/"'}
        expected={'s':'active','b':True,'t':123,'(uo)':[0,'/']}
        for kind,text in values.items():self.assertEqual(manager.parse_value(kind,kind+' '+text),expected[kind])
        for kind,text in [('b','b 1'),('t','t true'),('t','t -1'),('s','s "active" extra'),('(uo)','(uo) true "/"')]:
            with self.assertRaises(ValueError):manager.parse_value(kind,text)
        with self.assertRaises(ValueError):manager.parse_value('s','b true')
    def test_unit_paths_are_closed_and_exact_properties_partitioned(self):
        unit,slc=manager.read_arguments(self.recipe)
        self.assertEqual(unit[2],'/org/freedesktop/systemd1/unit/'+self.recipe.name.replace('.','_2e'))
        names=set(unit[4:])|set(slc[4:])
        self.assertEqual(names,{n for n,_,_ in self.recipe.properties}|{'ActiveState','SubState','LoadState','Transient','ControlGroup','Job'})
        bad=replace(self.recipe,properties=tuple((n,k,int(v) if type(v) is bool else v) for n,k,v in self.recipe.properties))
        with self.assertRaises(ValueError):manager.start_arguments(bad)
    def test_complete_typed_readback_projects_to_slice_verifier(self):
        values={n:v for n,_,v in self.recipe.properties}|dict(ActiveState='active',SubState='active',
            LoadState='loaded',Transient=True,ControlGroup='/'+self.recipe.name,Job=[0,'/'])
        types=manager.property_types(self.recipe)
        def render(request):
            lines=[]
            for name in request[4:]:
                value=values[name];kind=types[name]
                text='0 "/"' if kind=='(uo)' else json.dumps(value)
                lines.append(kind+' '+text)
            return ('\n'.join(lines)+'\n').encode()
        unit,slc=(render(request) for request in manager.read_arguments(self.recipe))
        self.assertEqual(manager.project_readback(self.recipe,unit,slc),values)
        self.assertIsNone(containment.verify_recipe_snapshot(self.recipe,values))
        for bad in (slc+b'extra\n',slc.replace(b'b true',b'b 1',1),b''):
            with self.assertRaises(ValueError):manager.project_readback(self.recipe,unit,bad)

    def test_controller_prerequisite_does_not_enable_missing_ancestors(self):
        self.assertIsNone(manager.verify_controllers(b'cpu memory pids io\n',b'cpu memory pids\n',b'domain\n'))
        for controllers,enabled,kind in [(b'cpu memory pids',b'cpu pids',b'domain\n'),(b'cpu memory',b'cpu memory pids',b'domain\n'),(b'cpu memory pids',b'cpu memory pids',b'threaded\n')]:
            with self.assertRaises(ValueError):manager.verify_controllers(controllers,enabled,kind)

if __name__=='__main__':unittest.main()
