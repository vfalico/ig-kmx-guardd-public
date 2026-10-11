import io,json,os,sys,time,unittest
sys.path.insert(0,os.path.join(os.path.dirname(__file__),"..","src"))
from ig_kmx_guardd.runtime import EventStream

class EventStreamTests(unittest.TestCase):
    def wait(self, stream, count):
        deadline=time.monotonic()+2
        while time.monotonic()<deadline:
            if stream.status()["total"]>=count:return
            time.sleep(.01)
        self.fail(f"stream did not reach {count}: {stream.status()}")

    def test_bounded_queue_reports_exact_oldest_drop(self):
        raw=b"".join(json.dumps({"rule_id":i}).encode()+b"\n" for i in range(5))
        stream=EventStream(io.BytesIO(raw),maximum=2); self.wait(stream,5)
        events,status=stream.drain()
        self.assertEqual([e["rule_id"] for e in events],[3,4])
        self.assertEqual((status["total"],status["dropped"],status["new_dropped"]),(5,3,3))
        events,status=stream.drain(); self.assertEqual(events,[]); self.assertEqual(status["new_dropped"],0)
        stream.close()

    def test_malformed_lines_are_counted_not_persisted(self):
        stream=EventStream(io.BytesIO(b'{"rule_id":7}\nnot-json\n[]\n'),maximum=4); self.wait(stream,1)
        deadline=time.monotonic()+2
        while time.monotonic()<deadline and stream.status()["malformed"]<2:time.sleep(.01)
        events,status=stream.drain()
        self.assertEqual(events,[{"rule_id":7}]); self.assertEqual(status["malformed"],2)
        self.assertEqual(status["new_malformed"],2); stream.close()

if __name__=='__main__':unittest.main()
