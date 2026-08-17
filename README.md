# Please - The Prompt-Layer Evaluation And Security Engine

## A structural prompt-injection detector for text processed by LLM agents.

Please (`plz`) is a prompt evaluation engine to look for injection techniques direct, indirect and otherwise. Before we start I think it's important to talk about why I started down this path. It would be trivial for me to slap together something that might be warmed over dinner of work I have done previously, or do something more in my wheelhouse that would come together faster and cost less tokens. 

## Quick Start

### Install + Dependencies

You can install the latest version from a clone of this repository:

`cargo install --path crates/cli`

The LLM judge is built in by default. If you want a binary that carries no HTTP client or TLS stack at all, build with `cargo install --path crates/cli --no-default-features` you lose the `--judge` arguement but other offline detections will work.

### How to use `plz`

Please can scan files, directories, and from `stdin` and look for potential prompt injection techniques. 

#### Scan a file or directory:

`plz scan skill.md` or `plz scan ./skills/`

#### Pipe remote text to `plz` via `stdin`

`curl -s https://totallysafebro.ai/prompt.txt | plz scan`

`plz` picks its output format from whether stdout is a terminal: prose when you are reading it, JSON when it is piped or redirected. Pass `--format` when you want to be sure either way:

`plz scan skill.md --format json`

#### Please Exit with some Codes:

To make `plz` easy to use with CI gates or pre-tool hook calls we provide exit codes to correspond to findings, errors, etc. 

```
0   clean
1   risk at or above threshold
3   risk below threshold
2   inconclusive (coverage gap, unreadable file, judge unavailable)
64  usage error
70  internal error (a bug — please report it)
```

#### Please Explain Why This Rule Fired:

If you want to dig in further to why a rule got triggered the `--explain` argument can give useful output:

`plz scan --explain skill.md`

#### Please fire from a Hook or CI Gate:

`plz scan --format json ./skills/ || exit 1`

#### Please Phone a Friend:

To call out to Anthropic compatible API platforms you can use the `--judge` option to get an opinion from an LLM.

`plz scan --judge skill.md    # structural tier + LLM second opinion`

It reads `ANTHROPIC_API_KEY` (or `ANTHROPIC_AUTH_TOKEN`, and `ANTHROPIC_BASE_URL` for a gateway). To see what it resolved without sending anything anywhere:

`plz judge --check`

The judge can only ever **narrow** a verdict — confirm a finding, or move it into the suppressed channel. It
cannot add a finding, cannot raise a severity, and cannot clear one. So it improves precision and cannot
improve recall. If it is unreachable, unauthenticated, times out, or answers with anything unexpected, the
verdict becomes `inconclusive` (exit 2) and never `clean`.

## Please Tell Me Why You Built This:

Truthfully, I did think what I was working on would come together quicker but...we do this not because it is easy, but because we thought it would be easy.

My idea is to build an extensible detection system in rust that can explore using custom rules to look for detections in an offline manner, while also allowing for external llm calls to judge content for prompt injection. I have used LlamaFirewall in the past on projects and felt it was heavy. LlamaFirewall combines a number of Meta backed open source projects using things like PromptGuard 2, Alignment Check, CodeShield and Pattern Matching as well.  I always wanted something smaller that could take advantage of both pattern matching / text matching and running machine learning models to pick apart senteance structure. https://meta-llama.github.io/PurpleLlama/LlamaFirewall/. 

https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M 
https://meta-llama.github.io/PurpleLlama/LlamaFirewall/docs/documentation/scanners/alignment-check
https://meta-llama.github.io/PurpleLlama/LlamaFirewall/docs/documentation/scanners/code-shield
https://meta-llama.github.io/PurpleLlama/LlamaFirewall/docs/documentation/scanners/prompt-guard-2

Why do I want this to exist? Well frankly as a big consumer of Cloudflare Workers and Workers AI the LlamaFirewall architecture is not suited to being run on the edge. Cloudflare does support Container workloads but because of their edge driven compute architecture cold start on a Durable Object driving a Container is significant and add onto that downloading the transformers for evaluation and it just got out of hand. This is an experiment to see if a lightweight solution in Rust can be extended out to support detection of multiple types of prompt injection and be expanded on down the line. Truthfully I was not able to get as much done as I wanted with this, my goal is to add typescript bindings via WASM and Go bindings as well. 

## Please Don't Overstate This:

This is barely a weekend project so to say it's in a final state would be untrue. We have a set of handcrafted test fixtures but it felt like the LLM driven development was over fitting our detection rules to win against the test fixtures vs the bigger datasets from Hugging Face. The test suite checks detection against curated fixtures and a set of hard negatives written by the same person who wrote the detectors, which is exactly the bias a real corpus exists to break.

**The evaluation harness (`crates/eval`) now exists and has been run.** `docs/research/eval-baseline.md` has the first corpus-measured numbers: 14 slices, ~74,000 rows, reproducible from committed manifests. The headline is that there isn't one — per-source detection ranges from 0% to 100% across twenty-one sources, and the source supplying half the corpus sits at 4%, so any aggregate is a weighted average of populations measuring different things. What can be said, with the slice named: **41.9%** on InjecAgent, **37.8%** on LLMail-Inject, and **0.0% false positives on 3,000 OR-Bench rows**. All at the `Low` floor rather than the shipped default.

The most useful thing it found is not a percentage. Varying placement independently of payload across 1,060 generated documents, detection is flat across every carrier format and every insertion position, and binary per payload: four of twenty payloads detected everywhere, sixteen detected nowhere. Detection is a function of the payload's words and nothing else — which is what a lexical tier *is*, but it is better to have measured it than to have argued it.

`docs/limits.md` is the honest list of what this does not do: quoted payloads can suppress detection, a structural tier reads form and not intent, multilingual *detection* is unmeasured (the corpus has zero non-English attacks, so only the false-positive half could be measured — 0.6%), sustained throughput misses its own criterion by about 4%, two named rules miss for reasons the eval run identified, and the fixture suite has known misses that are named in the tests rather than hidden. Read it before trusting a clean verdict.
