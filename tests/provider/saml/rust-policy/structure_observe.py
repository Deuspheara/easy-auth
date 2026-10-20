"""Replay original controls and confirmed incomplete-document cases unchanged."""
from base64 import b64decode, b64encode

import policy_observe as policy

MALFORMED = {"structure-trailing-open", "structure-trailing-response",
             "structure-trailing-child", "structure-trailing-nested"}
AFTER = {"structure-healthy-after-response", "structure-healthy-after-assertion"}


def corpus(port):
    data, original_keys = policy.corpus(port)
    rows = [line.decode().split("\t") for line in data.splitlines()]
    extra = []
    for row in rows:
        case, mode, encoded, certificates = row
        if case not in policy.POSITIVE:
            continue
        xml = b64decode(encoded)
        if case == "profile-healthy-response":
            # Malformed fixture construction only. Original signed bytes remain
            # intact; appended input is never removed before candidate parsing.
            name = xml.index(b":Response")
            start = xml.rfind(b"<", 0, name)
            tag = xml[start:xml.index(b">", start) + 1]
            for name, suffix in [
                ("structure-trailing-open", b"<dangling>"),
                ("structure-trailing-response", tag),
                ("structure-trailing-child", tag + b"<child/>"),
                ("structure-trailing-nested", tag + b"<child>"),
            ]:
                extra.append([name, mode, b64encode(xml + suffix).decode(), certificates])
        target = case.removeprefix("profile-healthy-")
        extra.append([f"structure-healthy-after-{target}", mode, encoded, certificates])
    keys = original_keys | {(row[0], row[1]) for row in extra}
    if len(extra) != 12 or len(keys) != 118:
        raise policy.parser.InfrastructureFailure("incomplete_structure_corpus")
    payload = data + "".join("\t".join(row) + "\n" for row in extra).encode()
    if len(payload) >= 2 * 1024 * 1024:
        raise policy.parser.InfrastructureFailure("transport_limit_exceeded")
    return payload, keys


def run():
    report = policy.run(corpus_builder=corpus, positive_cases=policy.POSITIVE | AFTER)
    rows = [row for row in report["exact_rows"] if row["case"] in MALFORMED]
    complete = len(rows) == 8 and all(row["error_class"] == "xml_rejected" for row in rows)
    report["document_completeness_passed"] = complete
    report["candidate_controls_passed"] &= complete
    report["status"] = "controls_passed" if report["candidate_controls_passed"] else "candidate_controls_failed"
    return report


if __name__ == "__main__":
    policy.main(run_report=run)
