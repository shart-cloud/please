"""Measure the current shipping CLI in one batch per mode; load is included."""
import hashlib,json,pathlib,subprocess,time
ROOT=pathlib.Path(__file__).resolve().parents[4]
OUT=ROOT/".cache/decision-poc-20260916"
def sha(p):
    with p.open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
def main():
    freeze=json.loads((OUT/"freeze.json").read_text())
    binary=ROOT/"target/release/plz"
    assert sha(binary)==freeze["plz_sha256"]
    pack=json.loads((OUT/"suite/pack.json").read_text())
    cases=[c for c in pack["cases"] if c["surface"]=="artifact_detection"]
    targets={str(OUT/"suite"/c["asset_path"]):c for c in cases}
    assert len(targets)==len(cases)==630
    for name,c in targets.items(): assert sha(pathlib.Path(name))==c["asset_sha256"]
    dest=OUT/"baseline"
    dest.mkdir()
    for mode in ("structural","structural_ml"):
        command=[str(binary),"scan","--profile","enforcement","--threshold","high","--format","json"]
        if mode=="structural_ml":command += ["--ml","--ml-config",str(OUT/"baseline-ml.json")]
        command+=list(targets)
        started=time.perf_counter()
        with (dest/(mode+".json")).open("w") as stdout,(dest/(mode+".stderr")).open("w") as stderr:
            result=subprocess.run(command,cwd=ROOT,stdout=stdout,stderr=stderr)
        elapsed=time.perf_counter()-started
        if result.returncode not in (0,1,2,3):raise RuntimeError("baseline failed: "+str(result.returncode))
        verdicts=json.loads((dest/(mode+".json")).read_text())
        if not isinstance(verdicts,list):verdicts=[verdicts]
        assert len(verdicts)==len(cases)
        seen=set();rows=[]
        for v in verdicts:
            c=targets[v["target"]["name"]]
            assert c["case_id"] not in seen
            seen.add(c["case_id"])
            blocked=v["outcome"]=="risk_found" and v["risk"] in ("high","critical")
            gaps=v.get("incomplete",[])
            rows.append(dict(case_id=c["case_id"],source=c["source"],label=c["ground_truth"]["label"],detected=blocked,incomplete=bool(gaps),risk=v["risk"],ml_present="ml" in v))
        if mode=="structural_ml": assert all(r["ml_present"] for r in rows),"ML coverage missing"
        (dest/(mode+"-summary.json")).write_text(json.dumps(dict(mode=mode,seconds_including_load=elapsed,binary_sha256=sha(binary),raw_sha256=sha(dest/(mode+".json")),cases=rows),indent=2)+"\n")
        print(json.dumps(dict(mode=mode,cases=len(rows),seconds=elapsed,detected=sum(r["detected"] for r in rows))),flush=True)
if __name__=="__main__":main()
