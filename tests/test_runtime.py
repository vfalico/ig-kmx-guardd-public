import hashlib,io,json,os,stat,struct,sys,tarfile,tempfile,unittest
sys.path.insert(0,os.path.join(os.path.dirname(__file__),"..","src"))
from ig_kmx_guardd.model import canonical,sha256_bytes
from ig_kmx_guardd.runtime import KernelInventory,VanillaIGRuntime

class InventoryFixture(KernelInventory):
 def __init__(self):super().__init__("/usr/sbin/bpftool");self.dumps={}
 def _dump(self,map_id):return self.dumps[map_id]

class RuntimeReadbackTests(unittest.TestCase):
 def fixture(self,generation=1,cgroup_id=55):
  inv=InventoryFixture();catalog={".rodata":5,"policy_state":1,"exec_rules":2,"write_rules":3,"network_rules":4}
  policy={"spec":{"denyExecutables":[{"id":5,"path":"/usr/bin/no"}],"denyWrites":[{"id":7,"path":"/tmp/no"}]}}
  exec_key=b"/usr/bin/no\0"+b"\0"*(256-len("/usr/bin/no")-1);write_path=b"/tmp/no\0"+b"\0"*(256-len("/tmp/no")-1)
  inv.dumps={5:[(b"\0"*4,struct.pack("<Q",cgroup_id)+b"\x01")],1:[(b"\0"*4,struct.pack("<IIII",1,0,generation,1))],
   2:[(exec_key,struct.pack("<II",5,0))],3:[(struct.pack("<Q",inv._fnv64("/tmp/no")),struct.pack("<II",7,0)+write_path)],4:[]}
  return inv,catalog,policy
 def test_exact_policy_state_rules_and_rodata(self):
  inv,catalog,policy=self.fixture();raw=canonical(policy)
  out=inv._policy_readback(catalog,{"generation":1,"cgroup_id":55,"policy":policy,"policy_raw":raw})
  self.assertTrue(out["verified"]);self.assertEqual(out["policy_digest"],sha256_bytes(raw));self.assertEqual(out["target_cgroup_id"],55)
  self.assertEqual(out["write_rules"],1);self.assertIn("authenticated canonical",out["policy_digest_source"])
 def test_rejects_state_generation_mismatch(self):
  inv,catalog,policy=self.fixture(generation=2)
  with self.assertRaisesRegex(ValueError,"policy_state"):
   inv._policy_readback(catalog,{"generation":1,"cgroup_id":55,"policy":policy,"policy_raw":canonical(policy)})
 def test_rejects_target_cgroup_mismatch(self):
  inv,catalog,policy=self.fixture(cgroup_id=56)
  with self.assertRaisesRegex(ValueError,"target cgroup"):
   inv._policy_readback(catalog,{"generation":1,"cgroup_id":55,"policy":policy,"policy_raw":canonical(policy)})
 def test_bpftool_byte_formats(self):
  self.assertEqual(KernelInventory._bytes([0,1,255]),b"\x00\x01\xff")
  self.assertEqual(KernelInventory._bytes(["0x00","01","ff"]),b"\x00\x01\xff")
  self.assertEqual(KernelInventory._bytes("00 01 ff"),b"\x00\x01\xff")
 def test_rejects_invalid_bpftool_bytes(self):
  with self.assertRaises(ValueError):KernelInventory._bytes(["0000"])
  with self.assertRaises(ValueError):KernelInventory._bytes([999])

class RuntimeImageTests(unittest.TestCase):
 def _fixture(self,root,reference="ghcr.io/vfalico/ig-kmx-guardd-public/agentpolicy:0.4.1"):
  log=os.path.join(root,"ig.log");ig=os.path.join(root,"ig")
  with open(ig,"w") as stream:
   stream.write("#!/usr/bin/env python3\nimport json,os,sys\nwith open(os.environ['FAKE_IG_LOG'],'a') as log: log.write(json.dumps(sys.argv[1:])+'\\n')\nif sys.argv[1:3]==['image','import']: sys.exit(int(os.environ.get('FAKE_IG_IMPORT_RC','0')))\nsys.exit(0)\n")
  os.chmod(ig,stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
  archive=os.path.join(root,"agentpolicy.oci.tar")
  annotations={} if reference is None else {"org.opencontainers.image.ref.name":reference}
  raw=json.dumps({"schemaVersion":2,"manifests":[{"annotations":annotations}]}).encode()
  with tarfile.open(archive,"w") as output:
   info=tarfile.TarInfo("index.json");info.size=len(raw);output.addfile(info,io.BytesIO(raw))
  def digest(path):
   with open(path,"rb") as stream:return "sha256:"+hashlib.sha256(stream.read()).hexdigest()
  return log,VanillaIGRuntime(ig,digest(ig),archive,digest(archive))
 def test_verified_archive_is_imported_and_same_reference_is_run(self):
  with tempfile.TemporaryDirectory() as root:
   log,runtime=self._fixture(root);old=os.environ.get("FAKE_IG_LOG");os.environ["FAKE_IG_LOG"]=log
   try:
    verification=runtime.verify()
    worker=runtime.start(55,b'{"apiVersion":"agentpolicy.gadget/v1alpha1","spec":{}}')
    worker.process.wait(timeout=2)
    runtime.terminate(worker)
   finally:
    if old is None:os.environ.pop("FAKE_IG_LOG",None)
    else:os.environ["FAKE_IG_LOG"]=old
   with open(log) as stream:commands=[json.loads(line) for line in stream]
   image="ghcr.io/vfalico/ig-kmx-guardd-public/agentpolicy:0.4.1"
   self.assertEqual(verification["gadget_image"],image)
   self.assertEqual(commands[0],["image","import",runtime.oci_archive])
   self.assertEqual(commands[1][:5],["run",image,"--verify-image=false","--pull=never","--runtimes="])
 def test_rejects_archive_without_exactly_one_reference(self):
  with tempfile.TemporaryDirectory() as root:
   _,runtime=self._fixture(root,reference=None)
   with self.assertRaisesRegex(ValueError,"exactly one"):runtime._archive_image()
 def test_import_failure_leaves_runtime_unverified(self):
  with tempfile.TemporaryDirectory() as root:
   log,runtime=self._fixture(root);old_log=os.environ.get("FAKE_IG_LOG");old_rc=os.environ.get("FAKE_IG_IMPORT_RC")
   os.environ["FAKE_IG_LOG"]=log;os.environ["FAKE_IG_IMPORT_RC"]="7"
   try:
    with self.assertRaisesRegex(ValueError,"IG image import failed"):runtime.verify()
   finally:
    if old_log is None:os.environ.pop("FAKE_IG_LOG",None)
    else:os.environ["FAKE_IG_LOG"]=old_log
    if old_rc is None:os.environ.pop("FAKE_IG_IMPORT_RC",None)
    else:os.environ["FAKE_IG_IMPORT_RC"]=old_rc
   self.assertIsNone(runtime.gadget_image)

if __name__=="__main__":unittest.main()
