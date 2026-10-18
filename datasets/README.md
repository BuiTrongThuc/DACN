# Datasets

These small files are synthetic examples for local testing and evaluation;
they do not contain real credentials or production log data.

- `ssh_examples.jsonl`: labeled failed/successful SSH events.
- `ssh_eval.jsonl`: expected aggregation outcomes for two sample source IPs.
- `windows_events.xmll`: safe Windows sequence fixture for parser/correlation tests.
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
