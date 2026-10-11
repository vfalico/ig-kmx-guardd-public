import hashlib,hmac,json,os,tempfile,time,unittest
from unittest.mock import patch
import sys
sys.path.insert(0,os.path.join(os.path.dirname(__file__),"..","src"))
from protocol_helpers import AUTHORIZER, envelope as signed_envelope

from ig_kmx_guardd.model import *
from ig_kmx_guardd.store import Store
from ig_kmx_guardd.receipt import Signer,decode_receipt
from ig_kmx_guardd.service import Config,GuardService
from ig_kmx_guardd.cgroup import CgroupIdentity

GADGET="sha256:"+"f"*64
AUTH=b"a"*32
SIGN=b"s"*32

class Proc:
 pid=4242
 def poll(self):return None
class Worker:
 process=Proc();pidfd=8
class Runtime:
 def __init__(self,fail=False):self.fail=fail;self.stopped=[]
 def verify(self):
  if self.fail:raise ValueError("artifact mismatch")
  return {"ig_sha256":"sha256:"+"1"*64,"oci_archive_sha256":"sha256:"+"0"*64}
 def start(self,cgid,policy):return Worker()
 def terminate(self,w):self.stopped.append(w)
class Inventory:
 def __init__(self,fail=False):self.fail=fail;self.released=[]
 def correlate(self,pid,expected):
  if self.fail:raise ValueError("exact map readback unavailable")
  spec=expected["policy"].get("spec",{})
  readback={"verified":True,"state":"ACTIVE","quarantined":False,"generation":expected["generation"],"failure_closed":True,
   "policy_digest":sha256_bytes(expected["policy_raw"]),"exec_rules":len(spec.get("denyExecutables",[])),
   "write_rules":len(spec.get("denyWrites",[])),"network_rules":0,"map_ids":{"policy_state":1,"exec_rules":2,"write_rules":3,"network_rules":4}}
  return {"worker_pid":pid,"objects":[{"kind":"link","id":9},{"kind":"map","id":1}],"map_readback":readback,
          "target_cgroup_id":expected["cgroup_id"],"assurance":"worker_fd_policy_map_readback"}
 def release(self,pid):self.released.append(pid)

def policy(network=False):
 return {"apiVersion":"agentpolicy.gadget/v1alpha1","kind":"AgentPolicy","metadata":{"name":"p","digest":"sha256:"+"9"*64},
  "spec":{"subject":{"taskUID":"task","sessionID":"sess"},"failureMode":"closed","denyWrites":[{"id":7,"path":"/tmp/denied"}],
  "denyNetworks":[{"id":8,"address":"1.2.3.4","port":443}] if network else []}}
def binding(pol,generation=1):return Binding("sess","attempt",generation,sha256_bytes(canonical(pol)),GADGET,"node-a")
class GuardTests(unittest.TestCase):
 def env(self, action, binding, body, request_id="request", nonce=None, issued=None, expected_state_version=None, **kwargs):
     if expected_state_version is None:
         expected_state_version = 0
         if binding is not None and action != "activate":
             try:
                 expected_state_version = self.store.session(binding.key())["state_version"]
             except KeyError:
                 pass
     return signed_envelope(action, binding, body, request_id, nonce, issued, expected_state_version=expected_state_version, **kwargs)

 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.store=Store(self.tmp.name+"/state.db",max_evidence=3)
  self.runtime=Runtime();self.inventory=Inventory()
  self.service=GuardService(Config("node-a",frozenset({1000}),GADGET,frozenset()),self.store,Signer(SIGN),AUTHORIZER,self.runtime,self.inventory,"boot")
  self.p=policy();self.b=binding(self.p)
 def tearDown(self):self.store.close();self.tmp.cleanup()
 def activate(self,env=None):
  request=env or self.env("activate",self.b,{"policy":self.p})
  with patch("ig_kmx_guardd.service.validate_cgroup_fd",return_value=CgroupIdentity(1,55,2,55)),patch("os.dup",return_value=99):
   return self.service.dispatch(1000,request,[6])
 def test_valid_activation_is_held_and_release_receipt_signed(self):
  out=self.activate();receipt=out["result"]["release_eligible_receipt"]
  payload=decode_receipt(receipt)
  self.assertEqual(out["result"]["state"],State.ACTIVE_VALIDATED);self.assertEqual(payload["stage"],Stage.ACTIVATION_VALIDATED)
  self.assertTrue(payload["claims"]["held"]);self.assertTrue(self.service.signer.verify(receipt));self.assertEqual(len(out["result"]["receipts"]),6)
  proof=payload["claims"]["kernel_proof"];self.assertEqual(proof["map_readback"]["policy_digest"],self.b.policy_digest)
 def test_inventory_failure_never_activates_and_cleans_worker(self):
  self.inventory.fail=True
  with self.assertRaisesRegex(ValueError,"readback"):self.activate()
  self.assertEqual(self.store.session(self.b.key())["state"],State.FREEZE_DESIRED)
  self.assertEqual(len(self.runtime.stopped),1);self.assertEqual(self.inventory.released,[4242])
 def test_caller_readback_is_rejected_before_reservation(self):
  request=self.env("activate",self.b,{"policy":self.p,"map_readback":{"verified":True}})
  with self.assertRaisesRegex(ValueError,"unknown=.*map_readback"):
   self.service.dispatch(1000,request,[6])
  self.assertEqual(self.store.db.execute("select count(*) from requests").fetchone()[0],0)
  with self.assertRaises(KeyError):self.store.session(self.b.key())
 def test_wrong_policy_digest_rejected_before_state(self):
  bad=Binding("sess","attempt",1,"sha256:"+"0"*64,GADGET,"node-a")
  with self.assertRaisesRegex(ValueError,"policy digest mismatch"):
   with patch("ig_kmx_guardd.service.validate_cgroup_fd",return_value=CgroupIdentity(1,55,2,55)):
    self.service.dispatch(1000,self.env("activate",bad,{"policy":self.p}),[6])
  with self.assertRaises(KeyError):self.store.session(bad.key())
 def test_network_policy_rejected(self):
  p=policy(True);b=binding(p)
  with self.assertRaisesRegex(ValueError,"network enforcement"):self.service.dispatch(1000,self.env("activate",b,{"policy":p}),[6])
 def test_non_one_generation_rejected(self):
  b=binding(self.p,2)
  with self.assertRaisesRegex(ValueError,"generation 1 only"):self.service.dispatch(1000,self.env("activate",b,{"policy":self.p}),[6])
 def test_peer_and_signature_authorization(self):
  with self.assertRaises(PermissionError):self.service.dispatch(2000,self.env("status",self.b,{}),[])
  env=self.env("status",self.b,{});env.authorization=env.authorization[:-1]+bytes([env.authorization[-1]^1])
  with self.assertRaises(PermissionError):self.service.dispatch(1000,env,[])
 def test_replay_and_idempotency(self):
  original=self.env("activate",self.b,{"policy":self.p},nonce="same-nonce",issued=int(time.time()))
  out=self.activate(original);same=self.service.dispatch(1000,original,[6]);self.assertEqual(out,same)
  with self.assertRaisesRegex(ValueError,"replayed nonce"):self.service.dispatch(1000,self.env("status",self.b,{},"r2","same-nonce"),[])
 def test_session_cannot_rebind_generation(self):
  self.activate();b2=binding(self.p,2)
  with self.assertRaisesRegex(ValueError,"generation 1 only"):self.service.dispatch(1000,self.env("activate",b2,{"policy":self.p},"r2","n2"),[6])
 def test_monotonic_lifecycle(self):
  self.store.create(self.b,{"ino":55})
  with self.assertRaisesRegex(ValueError,"non-monotonic"):self.store.transition(self.b.key(),State.DEACTIVATED)
 def test_recovery_never_infers_active(self):
  self.store.create(self.b,{"dev":1,"ino":55,"mount_id":2,"cgroup_id":55});self.store.transition(self.b.key(),State.ACTIVATING);self.store.transition(self.b.key(),State.ACTIVE_VALIDATED)
  self.store.recover();self.assertEqual(self.store.session(self.b.key())["state"],State.RECONCILING)
  with patch("ig_kmx_guardd.service.validate_cgroup_fd",return_value=CgroupIdentity(1,55,2,55)), patch("ig_kmx_guardd.service.read_events",return_value={"frozen":1}), patch("ig_kmx_guardd.service.os.dup",return_value=78):
   out=self.service.dispatch(1000,self.env("reconcile",self.b,{},"r3","n3"),[6]);self.assertEqual(out["result"]["state"],State.TERMINATING)
 def test_evidence_is_bound_and_bounded(self):
  self.store.create(self.b,{"ino":55})
  for i in range(5):self.service.dispatch(1000,self.env("evidence",self.b,{"event":{"decision":"DENY","i":i},"source_policy":"P","source_rule":"R"},f"e{i}",f"x{i}"),[])
  self.assertEqual(self.store.db.execute("select count(*) from evidence").fetchone()[0],3)
 def test_stale_envelope_and_unknown_fields(self):
  with self.assertRaisesRegex(ValueError,"stale"):
   self.env("status",self.b,{},issued=1,expires_at=2)
  from protocol_helpers import BUILDER
  frame=BUILDER.frame("status","unknown-field",self.b,{},expected_state_version=0)
  raw=frame.encode()+b"\x72\x00" # unknown length-delimited field 14
  with self.assertRaisesRegex(ValueError,"unknown protobuf field"):
   Envelope.from_frame(raw)


if __name__=="__main__":unittest.main()
