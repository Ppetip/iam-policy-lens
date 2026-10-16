import unittest
import tool

class BehaviorTests(unittest.TestCase):
    def test_case_0(self):
        self.assertEqual([x["kind"] for x in tool.analyze({'policy': {'Statement': []}})], [])

    def test_case_1(self):
        self.assertEqual([x["kind"] for x in tool.analyze({'policy': {'Statement': {'Effect': 'Allow', 'Action': '*', 'Resource': '*'}}})], ['wildcard_action', 'all_resources', 'passrole_scope'])

    def test_case_2(self):
        self.assertEqual([x["kind"] for x in tool.analyze({'policy': {'Statement': [{'Effect': 'Deny', 'Action': '*', 'Resource': '*'}]}})], [])

    def test_missing_required_input(self):
        with self.assertRaises((KeyError, ValueError, TypeError)):
            tool.analyze({})


    def test_conditions_are_visible_not_silently_trusted(self):
        result=tool.analyze({'policy':{'Statement':[{'Effect':'Allow','Action':'*','Resource':'*','Condition':{'StringEquals':{'demo':'x'}}}]}})
        self.assertTrue(all(x['conditional'] for x in result))
    def test_exact_resource_passrole_not_flagged(self):
        self.assertEqual(tool.analyze({'policy':{'Statement':[{'Effect':'Allow','Action':'iam:PassRole','Resource':'arn:aws:iam::123456789012:role/demo'}]}}),[])
    def test_public_principal(self):
        result=tool.analyze({'policy':{'Statement':[{'Effect':'Allow','Action':'s3:GetObject','Resource':'arn:demo','Principal':{'AWS':'*'}}]}})
        self.assertEqual(result[0]['kind'],'public_principal')
