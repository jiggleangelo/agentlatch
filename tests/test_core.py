import json, tempfile, unittest
from pathlib import Path
from agentgate.audit import DemoAuditLog
from agentgate.clock import FakeClock
from agentgate.identity import AgentRegistry, AuthError
from agentgate.keys import KeyRing
from agentgate.policy import PolicyEngine
from agentgate.release_check import REQUIRED, check
from agentgate.sample_data import POLICY
from agentgate.tokens import TokenError, TokenService
from agentgate.vault import SealedMemoryVault

class CoreTests(unittest.TestCase):
    def setUp(self):
        self.clock=FakeClock(); self.registry=AgentRegistry(self.clock); self.agent,self.secret=self.registry.register("invoice-bot")
    def test_identity(self):
        self.assertIs(self.registry.authenticate(self.agent.agent_id,self.secret),self.agent)
        self.assertNotIn(self.secret,repr(self.registry.agents))
        with self.assertRaises(AuthError): self.registry.authenticate(self.agent.agent_id,"wrong")
        self.registry.revoke(self.agent.agent_id)
        with self.assertRaises(AuthError): self.registry.authenticate(self.agent.agent_id,self.secret)
    def test_tokens_rotation_expiry(self):
        keys=KeyRing(); service=TokenService(keys,self.registry,self.clock); token,claims=service.issue(self.agent,["x"],999)
        self.assertEqual(claims["exp"]-claims["iat"],300); old=claims["kid"]; keys.rotate(); self.assertEqual(service.verify(token)["sub"],self.agent.agent_id)
        keys.retire(old)
        with self.assertRaises(TokenError): service.verify(token)
    def test_policy_and_audit(self):
        policy=PolicyEngine(self.clock,POLICY)
        self.assertTrue(policy.evaluate(self.agent,"payments.refund",{"amount":40,"currency":"EUR","order_id":"O"}).allowed)
        self.assertEqual(policy.evaluate(self.agent,"payments.refund",{"amount":400,"currency":"EUR","order_id":"O"}).reason,"constraint_failed:amount.max")
        audit=DemoAuditLog(self.clock); audit.append("tool.call",self.agent.agent_id,args={"amount":40}); self.assertEqual(audit.verify(),(True,None)); self.assertNotIn("40",audit.export_jsonl())
        with self.assertRaises(PermissionError): audit._tamper_for_demo(0)
        self.assertEqual(audit.verify(),(True,None))
    def test_audit_demo_tampering_is_disabled_by_default(self):
        audit=DemoAuditLog(self.clock)
        audit.append("tool.call",self.agent.agent_id,args={"amount":40})
        with self.assertRaisesRegex(PermissionError,"demo tampering disabled"):
            audit._tamper_for_demo(0)
        self.assertEqual(audit.verify(),(True,None))
    def test_vault_and_release(self):
        vault=SealedMemoryVault(); self.assertTrue(vault.put("contact","person@example.test").startswith("vref_")); self.assertNotIn("person@example.test",repr(vault)); self.assertFalse(any(x in dir(vault) for x in ("get","list","export")))
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(set(check(directory)),set(REQUIRED))
            for name in REQUIRED: Path(directory,name).write_text("Signed-off-by: Human role\n")
            self.assertEqual(check(directory),[])
if __name__ == "__main__": unittest.main()
