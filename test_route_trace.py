import copy
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import route_trace as rt

CASES = {s["id"]:s for s in json.loads((rt.BASE/"scenarios.json").read_text())}
EXPECTED = {"export-filter":"export_denied","import-filter":"import_denied","upstream-missing":"input_absent",
            "recursive-lookup":"unresolved","peer-offline":"peer_down","advertised":"advertised",
            "transient-export":"export_denied","incomplete-export":"handoff",
            "other-selection":"handoff","conflicting-capture":"handoff"}

class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.file = Path(self.tmp.name)/'runs.sqlite3'
        self.db = rt.connect(self.file)
        self.addCleanup(lambda:self.db.close())

    def begin(self, name, model=""):
        s = rt.new_state(copy.deepcopy(CASES[name]),model)
        with rt.transaction(self.db):rt.save(self.db,s)
        return s["run_id"]

    def test_ten_labeled_cases(self):
        for case, expected in EXPECTED.items():
            with self.subTest(case=case):
                s = rt.advance(self.db,self.begin(case))
                self.assertEqual((s["phase"],s["outcome"]),("awaiting_review",expected))
                self.assertLessEqual(len(s["evidence"]),6)
                self.assertTrue(all(v<=2 for v in s["attempts"].values()))
                if expected in rt.PROOFS:
                    self.assertTrue(all(s["evidence"][t]["value"]==v for t,v in rt.PROOFS[expected].items()))

    def test_resume_after_reopen(self):
        rid = self.begin("recursive-lookup")
        partial = rt.advance(self.db,rid,1)
        self.db.close()
        self.db = rt.connect(self.file)
        final = rt.advance(self.db,rid)
        self.assertEqual(final["trace"][:len(partial["trace"])],partial["trace"])
        self.assertEqual(final["outcome"],"unresolved")
        self.assertTrue(all(x==1 for x in final["attempts"].values()))

    def test_transient_and_persistent_failures(self):
        a=rt.advance(self.db,self.begin("transient-export"))
        b=rt.advance(self.db,self.begin("incomplete-export"))
        self.assertEqual(a["attempts"]["export_policy"],2)
        self.assertEqual(b["evidence"]["export_policy"]["value"],"unknown")
        self.assertIn("export_policy",rt.report(b).split("## Engineer handoff")[1])

    def test_review_gate_and_export_idempotence(self):
        rid=self.begin("export-filter")
        p=Path(self.tmp.name)/"incident.md"
        with self.assertRaises(ValueError):rt.review(self.db,rid,"approve","premature")
        rt.advance(self.db,rid)
        with self.assertRaises(ValueError):rt.export(self.db,rid,p)
        self.assertFalse(p.exists())
        s=rt.review(self.db,rid,"approve","Verified the evidence.")
        self.assertEqual(s,rt.review(self.db,rid,"approve","Verified the evidence."))
        rt.export(self.db,rid,p)
        rt.export(self.db,rid,p)
        self.assertEqual(p.read_text(),rt.report(s))
        p.write_text("other work")
        with self.assertRaises(ValueError):rt.export(self.db,rid,p)
        self.assertEqual(p.read_text(),"other work")

    def test_rejection(self):
        rid=self.begin("other-selection");rt.advance(self.db,rid)
        rt.review(self.db,rid,"reject","Collect more evidence")
        with self.assertRaises(ValueError):rt.export(self.db,rid,Path(self.tmp.name)/"out.md")
        with self.assertRaises(ValueError):rt.review(self.db,rid,"approve","override")

    def test_missing_fields_and_unsupported_values(self):
        s=copy.deepcopy(CASES["export-filter"])
        del s["reads"]["export_policy"]
        self.assertEqual(rt.new_state(s)["phase"],"investigating")
        s["reads"]["selected"]["value"]="apparently"
        with self.assertRaises(ValueError):rt.validate(s)

    def test_model_fallback(self):
        with patch.object(rt,"model_choice",side_effect=OSError("offline")) as model:
            s=rt.advance(self.db,self.begin("peer-offline","fixture"))
        self.assertEqual(model.call_count,1)
        self.assertEqual(s["outcome"],"peer_down")
        self.assertTrue(any(e["event"]=="planner_fallback" for e in s["trace"]))

    def test_model_policy_selects_only_available_reads(self):
        class Reply:
            def __init__(self,tool): self.tool=tool
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def read(self):return json.dumps({"message":{"content":json.dumps({"tool":self.tool})}}).encode()
        s=rt.new_state(CASES["export-filter"],"test")
        with patch.object(rt.request,"urlopen",return_value=Reply("export_policy")):
            self.assertEqual(rt.plan(s)["choice"],"export_policy")
        with patch.object(rt.request,"urlopen",return_value=Reply("change_policy")):
            result=rt.plan(s)
            self.assertEqual(result["model"],"")
            self.assertIn(result["choice"],rt.TOOLS)

if __name__=="__main__":unittest.main()
