"""命令行入口：``python -m solution --input cases.json --output result.json``。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .diff import diff_plan
from .errors import ERROR_CODES, AuditError
from .parser import SCHEMA_VERSION, load_specs
from .policy import Auditor
from .search import Planner


def _violation_dict(v) -> dict:
    return {
        "constraint_id": v.constraint_id,
        "kind": v.kind,
        "protocol": v.protocol,
        "source_service": v.source_service,
        "destination_service": v.destination_service,
        "source_instance": v.source_instance,
        "destination_instance": v.destination_instance,
        "interval": [v.interval[0], v.interval[1]],
        "detail": v.detail,
    }


def audit_one(spec: Spec) -> dict:
    auditor = Auditor(spec)
    planner = Planner(spec, auditor)

    initial_violations = auditor.violations(0)
    final_violations = auditor.violations(spec.full_mask)
    result: dict = {
        "case_id": spec.case_id,
        "groups": list(spec.groups),
        "services": list(spec.services),
        "port_domain": [spec.port_domain[0], spec.port_domain[1]],
        "initial_state_valid": not initial_violations,
        "final_state_valid": not final_violations,
    }
    if initial_violations:
        result["status"] = "error"
        result["error_code"] = "E_INITIAL"
        result["violations"] = [_violation_dict(v) for v in initial_violations]
        return result
    if final_violations:
        result["status"] = "error"
        result["error_code"] = "E_FINAL"
        result["violations"] = [_violation_dict(v) for v in final_violations]
        return result

    search = planner.solve()
    result["reachable_state_count"] = len(search.reachable_states)
    result["reachable_states"] = [
        {"mask": m, "completed_groups": planner._completed(m)} for m in search.reachable_states
    ]
    if search.found:
        result["status"] = "plan_found"
        result["sequence"] = search.sequence
        result["steps"] = diff_plan(auditor, spec, search.sequence)
    else:
        result["status"] = "no_plan"
        result["best_reachable"] = {
            "mask": search.best_mask,
            "completed_groups": search.best_completed,
            "completed_count": len(search.best_completed),
        }
        result["next_step_blocks"] = [
            {
                "group": b.group,
                "reachable": b.reachable,
                "reason": b.reason,
                "missing_prerequisites": b.missing_prerequisites,
                "violations": [_violation_dict(v) for v in b.violations],
            }
            for b in search.next_step_blocks
        ]
    return result


def build_document(input_path: str) -> dict:
    specs = load_specs(input_path)
    return {
        "schema_version": SCHEMA_VERSION,
        "error_codes": ERROR_CODES,
        "results": [audit_one(spec) for spec in specs],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="solution",
        description="离线服务分区策略审计器",
    )
    parser.add_argument("--input", required=True, help="输入 cases.json 路径")
    parser.add_argument("--output", required=True, help="输出 result.json 路径")
    args = parser.parse_args(argv)

    try:
        document = build_document(args.input)
    except AuditError as exc:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "status": "error",
            "error_code": exc.code,
            "error_message": str(exc),
            "error_codes": ERROR_CODES,
        }
        try:
            Path(args.output).write_text(
                json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        except OSError:
            pass
        print(f"[{exc.code}] {exc}", file=sys.stderr)
        return 2

    try:
        Path(args.output).write_text(
            json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except OSError as exc:
        print(f"[E_IO] 无法写入输出文件 {args.output}: {exc}", file=sys.stderr)
        return 2

    statuses = [r.get("status") for r in document["results"]]
    print(
        f"审计完成：{len(statuses)} 个 case，"
        f"plan_found={statuses.count('plan_found')}，"
        f"no_plan={statuses.count('no_plan')}，"
        f"error={statuses.count('error')}；结果已写入 {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
