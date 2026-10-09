import hashlib
import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch
import yaml
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
import compare_reviews
import prepare_comparison
import eval_faults
import g6_gate
import control_checks
from llm_observations import assess
from g6_observe import observe

class Evaluation(unittest.TestCase):
    def test_comparison_packets_exclude_answer_and_case_labels(self):
        cases=[{'id':'g4-pos-secret-label','held_out':True,'title':'answer hint','notes':'gold answer',
                'input':{'kind':'code','snippet':'do_work()'},'expected':{'should_flag':True}}]
        with tempfile.TemporaryDirectory() as directory:
            output=pathlib.Path(directory)/'experiment'
            manifest=prepare_comparison.prepare(cases,output)
            packet=(output/'packets/case-0001.json').read_text()
            for forbidden in ('g4-pos-secret-label','answer hint','gold answer','expected','should_flag'):
                self.assertNotIn(forbidden,packet)
            self.assertEqual(manifest['status'],'prepared_not_executed')
            with self.assertRaises(FileExistsError):prepare_comparison.prepare(cases,output)
    def test_empty_or_malformed_redteam_never_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            path=pathlib.Path(directory)/'report.json'
            for rows in ([],{},[None],[{'success':'true'}]):
                path.write_text(json.dumps({'results':{'results':rows}}))
                collector=g6_gate.Collector(*g6_gate.load_catalog())
                g6_gate.ingest_promptfoo_redteam(collector,str(path),None)
                self.assertEqual(g6_gate.build(collector,'shadow',g6_gate.now())[0]['status'],'incomplete')
    def test_tool_error_cannot_be_hidden_by_successful_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            path=pathlib.Path(directory)/'report.json'
            path.write_text(json.dumps({'results':{'results':[{'success':True}]}}))
            collector=g6_gate.Collector(*g6_gate.load_catalog())
            g6_gate.ingest_promptfoo_eval(collector,str(path),2)
            self.assertEqual(collector.tools[0]['state'],'error')
            self.assertEqual(collector.coverage['promptfoo-execution']['state'],'untested')
    def test_faults_really_return_expected_states(self):
        for p in (ROOT/'evals/cases').glob('**/*.yaml'):
            c=yaml.safe_load(p.read_text())
            if c['expected'].get('gate_status'):
                with self.subTest(case=c['id']):self.assertEqual(eval_faults.run(c),c['expected']['gate_status'])
    def test_control_counterexamples(self):
        self.assertEqual(control_checks.check({'headers':{'Content-Type':'text/html','Content-Security-Policy':"default-src 'self'"},'tools':[{'name':'refund_payment','require_confirmation':True}]}),[])
        self.assertEqual(control_checks.check({'tools':['refund_payment']}),['vibesec.g4.missing-hitl'])
    def test_missing_telemetry_is_unknown(self):
        rules,coverage=assess({})
        self.assertFalse(rules);self.assertEqual(set(coverage.values()),{'untested'})
        rules,coverage=assess({'tool_events':[],'usage':{'input_tokens':2,'cost_usd':0}})
        self.assertFalse(rules);self.assertEqual(set(coverage.values()),{'pass'})
    def test_malformed_telemetry_does_not_pass(self):
        for cost in (float("nan"), float("inf"), -1, True):
            _, coverage = assess({"tool_events": [None], "usage": {"input_tokens": 1, "cost_usd": cost}})
            self.assertEqual(coverage["excessive_agency"], "untested")
            self.assertEqual(coverage["denial_of_wallet_cost"], "untested")

    def test_cost_and_agency_produce_real_observations(self):
        class Client:
            def request(self,*args,**kwargs):return 200,json.dumps({'tool_events':[{'name':'delete_customers','executed':True,'human_approved':False}],'usage':{'input_tokens':20000,'cost_usd':0.2}})
        result=observe(Client())
        self.assertEqual(set(result['rules']),{'vibesec.g6.excessive-agency','vibesec.g6.denial-of-wallet'})
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'obs.json';p.write_text(json.dumps(result))
            collector=g6_gate.Collector(*g6_gate.load_catalog())
            g6_gate.ingest_observations(collector,str(p))
            self.assertTrue(collector.results)
    def test_comparison_requires_all_three_arms_and_evidence(self):
        case={'id':'c','held_out':True,'expected':{'should_flag':True}}
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);(root/'evidence.json').write_text('{}')
            records=[]
            for arm,families in [('single',['a']),('same_family',['a','a']),('cross_family',['a','b'])]:
                records.append({'arm':arm,'case_id':'c','reviewers':[{'family':f,'model':'version-1','state':'ran','round1_independent':True} for f in families],'decision':'flag','cost_usd':0.01,'human_seconds':1,'evidence_ref':'evidence.json','evidence_sha256':hashlib.sha256(b'{}').hexdigest()})
            self.assertEqual(compare_reviews.compare([case],records,root)['status'],'complete')
            self.assertEqual(compare_reviews.compare([case],records[:-1],root)['status'],'incomplete')
            records[-1]['requires_human']=True
            self.assertEqual(compare_reviews.compare([case],records,root)['status'],'incomplete')
            records[-1]['requires_human']=False;records[-1]['evidence_sha256']='bad'
            self.assertEqual(compare_reviews.compare([case],records,root)['status'],'incomplete')

if __name__=='__main__':unittest.main()
