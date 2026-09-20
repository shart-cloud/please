"""Render saved aggregate metrics as a standalone, readable HTML report."""
import json,pathlib,html
R=pathlib.Path(__file__).resolve().parents[4];O=R/".cache/laya-experiment-20260919"
d=json.loads((O/"comparison.json").read_text());esc=html.escape
def table(headers,rows):
 return "<table><thead><tr>"+"".join("<th>"+esc(str(x))+"</th>" for x in headers)+"</tr></thead><tbody>"+"".join("<tr>"+"".join("<td>"+esc(str(x))+"</td>" for x in row)+"</tr>" for row in rows)+"</tbody></table>"
def fraction(v):return f'{v["correct"]}/{v["total"]} ({v["correct"]/v["total"]:.1%})'
body="<h1>Laya vs Jev</h1><p class=lead>Local development experiment · September 19, 2026</p>"
body+="<p>Two local checkpoints, two question sets, 1,200 public cases and 600 contextual cases. Jev is the historical matched-case baseline. No new Jev API requests or shipping changes.</p>"
body+="<h2>Attack detection</h2>"
rows=[]
for name,m in d["partitions"]["public"]["systems"].items():
 rows.append([name,fraction(m["recalls"]["injection"]),f'{m["false_alarms"]}/600',f'{m["decided"]}/1200',1200-m["valid_inference"]])
body+=table(["System","Attacks detected","Benign false alarms","Determinate decisions","Input/runtime gaps"],rows)
body+="<h2>Caller-context advice</h2>";rows=[]
for name,m in d["partitions"]["contextual"]["systems"].items():
 rows.append([name,f'{m["macro_recall"]:.1%}',*[m["recalls"][x]["correct"] for x in ["aligned_instruction","conflicting_instruction","non_instruction","indeterminate"]],m["false_conflicts"],f'{m["answerable_decided"]}/450'])
body+=table(["System","Macro recall","Aligned /150","Conflict /150","Analysis /150","Unknown /150","False conflicts","Answerable coverage"],rows)
body+="<p><strong>Exact</strong>: original Jev questions and state. <strong>Full</strong>: compact Laya questions with the same state. Laya scores use a frozen 0.7 top-support and 0.15 margin gate. Entropy confidence is recorded but not gated.</p>"
body+="<h2>Native choices before gating</h2>"
body+=table(["System","Attacks detected /600","Benign false alarms /600"],[[n,m["native_recalls"]["injection"]["correct"],m["native_false_alarms"]] for n,m in d["partitions"]["public"]["systems"].items()])
body+="<h2>Runtime</h2><p>Local GPU whole-decision medians exclude startup and rejected inputs. Jev numbers are historical API timing; this is not a same-day latency comparison.</p>"
body+=table(["System","Surface","Whole decision median, ms","Local forward call median, ms"],[[n,p,round(m["decision_ms_median"],1) if m["decision_ms_median"] is not None else "N/A",round(m["inference_ms_median"],1) if m["inference_ms_median"] is not None else "API"] for p,v in d["partitions"].items() for n,m in v["systems"].items()])
body+="<h2>Diagnostic controls</h2>"
body+=table(["Checkpoint / control","Final choices changed /60","Native choices changed /60"],[[n,v["changed_final"],v["changed_native"]] for n,v in d["controls"].items()])
body+="<h2>Evidence limits</h2><p>All cases are exposed development material. Context labels await independent review; delivery variants are correlated. Native abstentions and failures remain in denominators. No threshold fitting, training, or default promotion occurred. The detailed Markdown/JSON include source strata, paired disagreements, common-fit comparisons and retained setup failures.</p>"
body+='<p><a href="report.md">Detailed report</a> · <a href="comparison.json">Metrics JSON</a></p>'
page='<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Laya vs Jev experiment</title><style>body{font:16px/1.55 system-ui,sans-serif;margin:40px auto;padding:0 24px;max-width:1120px;background:#f5f7f8;color:#16242d}h1{font-size:44px;margin-bottom:0}h2{margin-top:38px}.lead{color:#506575;margin-top:3px}table{border-collapse:collapse;width:100%;font-size:14px;background:white}th,td{text-align:left;border-bottom:1px solid #d8e1e5;padding:10px 12px}th{background:#173c47;color:white}tbody tr:nth-child(even){background:#eef3f5}a{color:#006b73}p{max-width:960px}@media(max-width:700px){table{display:block;overflow-x:auto}}</style><main>'+body+'</main></html>'
(O/"report.html").write_text(page)
(pathlib.Path("/mnt/c/Users/jg/benchmark-preview/laya-experiment-20260919")/"report.html").write_text(page)
print("Rendered standalone comparison report.")
