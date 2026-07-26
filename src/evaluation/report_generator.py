"""Report generation utilities for benchmark and comparison outputs."""

from __future__ import annotations

import csv
import html
import json
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from .comparison_engine import StrategyComparison


class EvaluationReportGenerator:
    """Generate markdown, html, json, and csv artifacts for evaluation outputs."""

    def write_json_report(self, payload: Mapping[str, object], output_path: Path) -> None:
        """Write machine-readable JSON report payload."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def write_csv_table(self, rows: Sequence[Mapping[str, object]], output_path: Path) -> None:
        """Write tabular rows to CSV for downstream analysis or charting."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if not rows:
            output_path.write_text("", encoding="utf-8")
            return

        fieldnames = sorted({key for row in rows for key in row.keys()})
        with output_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow(row)

    def write_markdown_summary(
        self,
        comparisons: Sequence[StrategyComparison],
        output_path: Path,
    ) -> None:
        """Write dissertation-ready markdown summary table for strategy ranking."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "# Benchmark Summary",
            "",
            "| Rank | Strategy | Precision | Recall | F1 | Accuracy | FP Rate | Disagreement |",
            "|---:|---|---:|---:|---:|---:|---:|---:|",
        ]
        for index, row in enumerate(comparisons, start=1):
            lines.append(
                "| "
                f"{index} | {row.strategy_name} | {row.metrics.precision:.3f} | "
                f"{row.metrics.recall:.3f} | {row.metrics.f1_score:.3f} | "
                f"{row.metrics.accuracy:.3f} | {row.false_positive_rate:.3f} | "
                f"{row.disagreement_rate:.3f} |"
            )
        output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def write_html_summary(
        self,
        comparisons: Sequence[StrategyComparison],
        output_path: Path,
    ) -> None:
        """Write compact HTML report for dashboard embedding or archival."""
        output_path.parent.mkdir(parents=True, exist_ok=True)

        header = (
            "<html><head><meta charset='utf-8'><title>Benchmark Summary</title></head><body>"
            "<h1>Benchmark Summary</h1>"
            "<table border='1' cellspacing='0' cellpadding='6'>"
            "<thead><tr>"
            "<th>Rank</th><th>Strategy</th><th>Precision</th><th>Recall</th><th>F1</th>"
            "<th>Accuracy</th><th>FP Rate</th><th>Disagreement</th>"
            "</tr></thead><tbody>"
        )

        rows = []
        for index, row in enumerate(comparisons, start=1):
            rows.append(
                "<tr>"
                f"<td>{index}</td>"
                f"<td>{html.escape(row.strategy_name)}</td>"
                f"<td>{row.metrics.precision:.3f}</td>"
                f"<td>{row.metrics.recall:.3f}</td>"
                f"<td>{row.metrics.f1_score:.3f}</td>"
                f"<td>{row.metrics.accuracy:.3f}</td>"
                f"<td>{row.false_positive_rate:.3f}</td>"
                f"<td>{row.disagreement_rate:.3f}</td>"
                "</tr>"
            )

        footer = "</tbody></table></body></html>"
        output_path.write_text(header + "".join(rows) + footer, encoding="utf-8")
