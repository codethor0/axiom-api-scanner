#!/usr/bin/env bash
# Shared jq assertions for read_trust_legend (finding detail) and operator_guide (execution detail).
# Sourced by scripts/benchmark_findings_local.sh and scripts/e2e_local.sh.

assert_read_trust_legend_shape() {
  local detail_json="$1"
  echo "$detail_json" | jq -e '
    (.read_trust_legend | type == "object") and
    (.read_trust_legend.severity | type == "string" and length > 0) and
    (.read_trust_legend.rule_declared_confidence | type == "string" and length > 0) and
    (.read_trust_legend.assessment_tier | type == "string" and length > 0) and
    (.read_trust_legend.evidence_summary | type == "string" and length > 0) and
    (.read_trust_legend.evidence_inspection | type == "string" and length > 0) and
    (.read_trust_legend.operator_assessment | type == "string" and length > 0) and
    (.read_trust_legend.finding_list_row | type == "string" and length > 0)
  ' >/dev/null
}

assert_operator_guide_shape() {
  local ex_json="$1"
  echo "$ex_json" | jq -e '
    (.operator_guide | type == "object") and
    (.operator_guide.phase_role | type == "string" and length > 0) and
    (.operator_guide.linkage_narration | type == "string" and length > 0) and
    (.operator_guide.summaries_mirror_redacted_snapshots | type == "string" and length > 0) and
    (.operator_guide.phase_execution_kind_alignment | type == "string" and length > 0) and
    (.operator_guide.summaries_list_detail_parity | type == "string" and length > 0) and
    (.operator_guide.cross_phase_filter_hint | type == "string" and length > 0) and
    (.operator_guide.phase_summary_compare_hint | type == "string" and length > 0)
  ' >/dev/null
}

# When both execution ids are present on a finding, evidence_comparison_guide must be non-empty (actionable GET paths).
assert_finding_evidence_comparison_when_paired() {
  local detail_json="$1"
  echo "$detail_json" | jq -e '
    if ((.baseline_execution_id // "") | length > 0) and ((.mutated_execution_id // "") | length > 0)
    then (.evidence_comparison_guide | type == "string" and length > 40)
    else true end
  ' >/dev/null
}
