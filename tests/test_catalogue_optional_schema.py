import json
import unittest

from agentgate.starter import generate_policy, import_catalogue


class OptionalCatalogueSchemaTests(unittest.TestCase):
    def test_required_catalogue_formats_accept_tools_without_properties(self):
        tool = {'name': 'files.read'}
        formats = [
            'files.read\n',
            json.dumps([tool]),
            json.dumps({'tools': [tool]}),
            json.dumps({'jsonrpc': '2.0', 'id': 1, 'result': {'tools': [tool]}}),
            json.dumps([dict(tool, inputSchema={})]),
            json.dumps([dict(tool, inputSchema={'type': 'object'})]),
            json.dumps([dict(tool, inputSchema={'type': 'object', 'properties': {}})]),
        ]
        expected = [{'name': 'files.read', 'description': '', 'properties': []}]
        for raw in formats:
            with self.subTest(raw=raw):
                tools, warnings = import_catalogue(raw)
                self.assertEqual(tools, expected)
                self.assertEqual(warnings, [])
                policy, todos = generate_policy(tools, ['a'], [('a', 'files.read')])
                self.assertEqual(policy, {'version': 1, 'rules': [
                    {'agent': 'a', 'tool': 'files.read', 'effect': 'allow', 'constraints': {}}
                ]})
                self.assertEqual(todos, [])

    def test_plain_text_tool_count_boundary(self):
        # 200 distinct lines are exactly the cap; line 201 exceeds it by one.
        names = ['tool' + str(index) for index in range(200)]
        tools, warnings = import_catalogue('\n'.join(names))
        self.assertEqual([tool['name'] for tool in tools], names)
        self.assertEqual(warnings, [])
        with self.assertRaisesRegex(ValueError, 'too_many_tools'):
            import_catalogue('\n'.join(names + ['tool200']))

    def test_property_count_boundary_preserves_schema_constraints(self):
        # 64 properties fit; 65 exceeds the cap. One selected pair yields one rule.
        properties = {'p' + str(index): {'type': 'integer', 'minimum': 0, 'maximum': 10}
                      for index in range(64)}
        definition = {'name': 'x', 'inputSchema': {'type': 'object', 'properties': properties}}
        tools, warnings = import_catalogue(json.dumps([definition]))
        self.assertEqual(len(tools[0]['properties']), 64)
        self.assertEqual(warnings, [])
        policy, todos = generate_policy(tools, ['a'], [('a', 'x')])
        self.assertEqual(len(policy['rules']), 1)
        self.assertEqual(policy['rules'][0]['constraints'],
                         {name: {'min': 0, 'max': 10} for name in properties})
        self.assertEqual(todos, [])
        properties['p64'] = {'type': 'integer', 'maximum': 10}
        with self.assertRaisesRegex(ValueError, 'too_many_properties'):
            import_catalogue(json.dumps([definition]))


if __name__ == '__main__':
    unittest.main()
