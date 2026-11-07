import json

from globalban.evaluation.protocol import evaluate_cases, load_labeled_cases


def test_labeled_protocol_reproduces_fixture_metrics(tmp_path):
    labels = tmp_path / "labels.jsonl"
    labels.write_text(
        "\n".join(
            [
                json.dumps({
                    "case_id": "benign",
                    "expected_detected": False,
                    "events": [{
                        "timestamp": "2025-01-01T00:00:00+00:00",
                        "event_id": 4624,
                        "fields": {"TargetUserName": "alice"},
                    }],
                }),
                json.dumps({
                    "case_id": "attack",
                    "expected_detected": True,
                    "events": [
                        {
                            "timestamp": "2025-01-01T00:00:00+00:00",
                            "event_id": 4624,
                            "fields": {"TargetUserName": "alice"},
                        },
                        {
                            "timestamp": "2025-01-01T00:00:01+00:00",
                            "event_id": 4688,
                            "fields": {"SubjectUserName": "alice"},
                        },
                        {
                            "timestamp": "2025-01-01T00:00:02+00:00",
                            "event_id": 4698,
                            "fields": {"SubjectUserName": "alice"},
                        },
                    ],
                }),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    report = evaluate_cases(load_labeled_cases(labels))

    assert report.cases == 2
    assert report.metrics.precision == 1.0
    assert report.metrics.recall == 1.0
    assert report.metrics.f1 == 1.0
