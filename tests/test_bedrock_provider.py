"""Bedrock 憑證與輸出邊界。 / Bedrock credential and output boundaries."""
import json
import pathlib
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import yaml
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]/'scripts'))
import review_provider as provider


class Bedrock(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        (self.root/'config/harness/roles').mkdir(parents=True)
        (self.root/'config/harness/roles/architecture.md').write_text('---\nprompt_version: architecture@2026-10-09.1\n---\nReview.')
        self.p = {'family':'anthropic','kind':'bedrock','aws_region':'us-east-1','api_key_env':'AWS_ACCESS_KEY_ID',
                  'model':'test-model','enabled':True,'allowed_data_classes':['internal'],'timeout_seconds':9}
        (self.root/'config/providers.yaml').write_text(yaml.safe_dump({'providers':{'bedrock':self.p}}))
        self.env = {'AWS_ACCESS_KEY_ID':'synthetic-access','AWS_SECRET_ACCESS_KEY':'synthetic-secret','AWS_SESSION_TOKEN':'synthetic-token'}
        self.packet = {'output_contract':'finding-opinion'}

    def call(self, classification='internal', env=None):
        return provider.call('bedrock','architecture',classification,self.packet,self.root,self.env if env is None else env)

    def test_no_network_for_disallowed_data_or_missing_secret(self):
        with patch.object(provider, '_bedrock') as backend:
            self.assertEqual(self.call('confidential')['state'],'refused')
            self.assertEqual(self.call(env={'AWS_ACCESS_KEY_ID':'synthetic-access'})['state'],'missing')
            backend.assert_not_called()

    def test_all_aws_credentials_are_redacted_in_results_and_rejections(self):
        reflected=' '.join(self.env.values())
        with patch.object(provider,'_bedrock',side_effect=[({'bad':reflected},'test',[]),
                         ({'verdict':'uncertain','rationale':reflected,'cited_evidence':[]},'test',[]) ]):
            result=self.call()
        self.assertEqual(result['state'],'ran')
        self.assertTrue(result['rejected_attempts'])
        for key in self.env.values():self.assertNotIn(key,json.dumps(result))

    def test_sdk_uses_explicit_identity_and_classifies_timeout(self):
        class SDKError(Exception):pass
        class SDKTimeout(SDKError):pass
        class ClientError(SDKError):pass
        exceptions=types.ModuleType('botocore.exceptions')
        for name,cls in [('BotoCoreError',SDKError),('ClientError',ClientError),('ConnectTimeoutError',SDKTimeout),('ReadTimeoutError',SDKTimeout)]:setattr(exceptions,name,cls)
        config=types.ModuleType('botocore.config');config.Config=lambda **kw:kw
        seen={}
        class Client:
            def converse(self,**kw):
                seen['request']=kw
                return {'output':{'message':{'content':[{'text':json.dumps({'verdict':'uncertain','rationale':'No evidence','cited_evidence':[]})}]}},'usage':{'inputTokens':3,'outputTokens':4}}
        class Session:
            def __init__(self,**kw):seen['identity']=kw
            def client(self,name,**kw):seen['config']=kw;return Client()
        boto=types.ModuleType('boto3');boto.Session=Session
        with patch.dict(sys.modules,{'boto3':boto,'botocore.config':config,'botocore.exceptions':exceptions}):
            result=self.call()
            self.assertEqual(result['state'],'ran')
            self.assertEqual(seen['identity']['aws_session_token'],self.env['AWS_SESSION_TOKEN'])
            self.assertEqual(seen['config']['config']['retries']['max_attempts'],0)
            with patch.object(Client,'converse',side_effect=SDKTimeout()):
                self.assertEqual(self.call()['state'],'timeout')
            with patch.object(Client,'converse',return_value={'output':{'message':{'content':[{'text':'no JSON'}]}}}):
                self.assertEqual(self.call()['state'],'error')
            with patch.object(Client,'converse',return_value={'output':None}):
                self.assertEqual(self.call()['state'],'error')
            with patch.object(Client,'converse',return_value={'stopReason':'guardrail_intervened'}) as invoke:
                self.assertEqual(self.call()['state'],'error')
                self.assertEqual(invoke.call_count,1)

    def test_malformed_transport_response_is_recorded_as_error(self):
        self.p['kind']='openai_compatible'
        self.p['base_url']='https://model.example.invalid/v1'
        (self.root/'config/providers.yaml').write_text(yaml.safe_dump({'providers':{'bedrock':self.p}}))
        for response in ({'choices':None}, {'choices':[None]}, {'choices':[{'message':None}]}, None):
            with self.subTest(response=response), patch.object(provider,'_post',return_value=response):
                result=self.call()
                self.assertEqual(result['state'],'error')
                self.assertIsNone(result['opinion'])

    def test_filter_or_truncation_does_not_trigger_format_retry(self):
        self.p.update(kind='openai_compatible',base_url='https://model.example.invalid/v1')
        (self.root/'config/providers.yaml').write_text(yaml.safe_dump({'providers':{'bedrock':self.p}}))
        for finish in ('content_filter','content_filter: OTHER','length'):
            with patch.object(provider,'_post',return_value={'choices':[{'finish_reason':finish}]}) as post:
                result=self.call()
                self.assertEqual(result['state'],'error');self.assertIn(finish,result['note'])
                self.assertEqual(post.call_count,1)

    def test_invalid_json_is_not_stored_and_reflected_key_is_not_leaked(self):
        self.p.update(kind='openai_compatible',base_url='https://model.example.invalid/v1')
        (self.root/'config/providers.yaml').write_text(yaml.safe_dump({'providers':{'bedrock':self.p}}))
        with patch.object(provider,'_post',return_value={'choices':[{'message':{'content':'invalid '+self.env['AWS_ACCESS_KEY_ID']}}]}):
            result=self.call()
        self.assertEqual(result['state'],'error')
        self.assertIsNone(result['rejected_attempts'][0]['response'])   # 無法解析的文字不保存（資料分級）
        self.assertNotIn(self.env['AWS_ACCESS_KEY_ID'],json.dumps(result))


if __name__=='__main__':unittest.main()
