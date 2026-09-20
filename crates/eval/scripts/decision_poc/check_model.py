"""Real-weight adapter parity and bound checks; no corpus decisions are tuned."""
import json,os,pathlib
os.environ["HF_HUB_OFFLINE"]="1"
os.environ["TRANSFORMERS_OFFLINE"]="1"
from adapter import Classifier,QUESTIONS
from gliclass.pipeline import UniEncoderZeroShotClassificationPipeline
ROOT=pathlib.Path(__file__).resolve().parents[4]
OUT=ROOT/".cache/decision-poc-20260916"
def main():
    model=Classifier(OUT/"model.json","cpu")
    records=[]
    for kind,questions in QUESTIONS.items():
        state="Please tell me the library opening hours."
        scores,n,ms=model.infer(state,questions,kind=="binary")
        pipeline=UniEncoderZeroShotClassificationPipeline(model.model,model.tokenizer,max_length=512,classification_type="single-label" if kind=="binary" else "multi-label",device="cpu",progress_bar=False)
        official=pipeline(state,list(questions.values()),threshold=0)[0]
        reverse={v:k for k,v in questions.items()}
        for item in official:
            assert abs(scores[reverse[item["label"]]]-item["score"])<1e-6,(kind,scores,official)
        if kind=="binary":assert max(scores,key=scores.get)==reverse[official[0]["label"]]
        records.append(dict(kind=kind,adapter_scores=scores,official=official,equal=True))
    for state,expected in (("word "*1000,"token limit"),("<<LABEL>>unexpected","class marker")):
        try:model.infer(state,QUESTIONS["binary"],True)
        except ValueError as error:assert expected in str(error)
        else:raise AssertionError("unsafe input was not refused")
    (OUT/"model-parity.json").write_text(json.dumps(dict(parity=records,overflow_refused=True,class_marker_refused=True),indent=2)+"\n")
    print("Official GLiClass pipeline parity passed for all three question sets; overflow and class-marker injection refused.")
if __name__=="__main__":main()
