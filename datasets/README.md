# Datasets

These small files are synthetic examples for local testing and evaluation;
they do not contain real credentials or production log data.

- `ssh_examples.jsonl`: labeled failed/successful SSH events.
- `ssh_eval.jsonl`: expected aggregation outcomes for two sample source IPs.
- `windows_events.xmll`: safe Windows sequence fixture for parser/correlation tests.
- `windows_eval_labels.jsonl`: reviewed sample labels for the reproducible
  sequence-detection protocol. Run `globalban-evaluate` to create a report.
- `atomic_evtx_manifest.json`: metadata and import instructions for the external
	Atomic-EVTX dataset; raw EVTX/JSON is intentionally not vendored here.

Atomic-EVTX reports 1,064 simulated Windows attack scenarios across twelve
categories. Use its unfiltered variant to test extraction, and the filtered
variants to test whether detection relies on obvious Atomic/tool strings. The
catalog loader is `globalban.evaluation.atomic_catalog`; it reads a locally
downloaded `full_list_of_attacks_simulated.csv` for technique metadata. The
source repository did not expose a license file during review, so verify
permission before redistributing or committing raw logs.

Do not add real authentication logs to version control. Such logs can contain
usernames, hostnames, and network identifiers.

Large upstream datasets are not runtime dependencies. Keep full downloads
outside Git (or use an approved Git LFS/artifact store), preserve their
licenses, and record the exact version and filtering method when producing a
benchmark. Temporary conversion output must not be committed.

## Optional AI knowledge sources

The repository can use two independent, locally downloaded sources when the AI
advisory is enabled:

- `..\AD-GEN\`: ATT&CK-aligned endpoint narratives.
- `WinLOLBIN-GT-dataset\`: labelled Windows LOLBin behaviour features.

The AI client indexes only a bounded local sample from each source and keeps
their labels separate. It adds matching records as references to an advisory;
it does not treat either dataset as ground truth and does not send the full
datasets to the API. Override the default locations with
`GLOBALBAN_ADGEN_PATH` and `GLOBALBAN_LOLBIN_DATASET_PATH`.

WinLOLBIN-GT's large CSV payload is distributed through its Zenodo release,
not the Git repository. Download it separately and place the processed CSV
under `WinLOLBIN-GT-dataset\` before expecting matches.
