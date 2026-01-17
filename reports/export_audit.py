import csv
import json
import os
import hashlib
from datetime import datetime, timezone
import sys
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common import config, logger, repo
from common.db import db


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def export_audit_report():
    ts = datetime.now(timezone.utc)
    date_part = ts.strftime("%Y-%m-%d")
    report_dir = "reports"
    os.makedirs(report_dir, exist_ok=True)
    filename_csv = f"{report_dir}/access_certification_{date_part}.csv"
    filename_json = f"{report_dir}/access_certification_{date_part}.json"

    logger.log(
        "export_audit",
        "start",
        f"Generating Audit Artifacts ({filename_csv}, {filename_json})",
        details={"db_url": config.DB_URL},
    )

    try:
        with db.get_connection() as conn:
            rows = repo.fetch_reviews_for_export(conn)

        if not rows:
            raise RuntimeError("No access review records to export (blocking empty artifact).")

        # Integrity: counts by status
        status_counts = {}
        for row in rows:
            status = row[5]
            status_counts[status] = status_counts.get(status, 0) + 1

        # Write CSV
        with open(filename_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Review ID",
                "Campaign ID",
                "User",
                "Role",
                "Risk Level",
                "Decision Status",
                "Reviewer Comment",
                "AI Risk Summary",
                "Created At",
                "Reviewed At",
                "Remediated At"
            ])
            writer.writerows(rows)

        # Write JSON canonical
        json_records = [
            {
                "review_id": r[0],
                "campaign_id": r[1],
                "user": r[2],
                "role": r[3],
                "risk_level": r[4],
                "status": r[5],
                "reviewer_comment": r[6],
                "ai_risk_summary": r[7],
                "created_at": r[8],
                "reviewed_at": r[9],
                "remediated_at": r[10],
            }
            for r in rows
        ]
        with open(filename_json, "w", encoding="utf-8") as jf:
            json.dump(json_records, jf, ensure_ascii=False, indent=2)

        # Hashes
        with open(filename_csv, "rb") as f:
            csv_hash = _sha256_bytes(f.read())
        with open(filename_json, "rb") as f:
            json_hash = _sha256_bytes(f.read())

        # Optional S3 upload
        if config.AUDIT_S3_BUCKET and not config.LOCAL_ONLY:
            s3 = boto3.client("s3")
            prefix = config.AUDIT_S3_PREFIX.rstrip("/")
            base_path = f"{prefix}/access_reviews/{date_part}" if prefix else f"access_reviews/{date_part}"
            s3_csv_key = f"{base_path}/access_certification.csv"
            s3_json_key = f"{base_path}/access_certification.json"

            common_meta = {
                "generated_at": ts.isoformat(),
                "record_count": str(len(rows)),
                "csv_sha256": csv_hash,
                "json_sha256": json_hash,
            }

            s3.upload_file(
                filename_csv,
                config.AUDIT_S3_BUCKET,
                s3_csv_key,
                ExtraArgs={"Metadata": common_meta, "ContentType": "text/csv"},
            )
            s3.upload_file(
                filename_json,
                config.AUDIT_S3_BUCKET,
                s3_json_key,
                ExtraArgs={"Metadata": common_meta, "ContentType": "application/json"},
            )
            s3_location = f"s3://{config.AUDIT_S3_BUCKET}/{base_path}"
        else:
            s3_location = None

        logger.log(
            "export_audit",
            "success",
            "Audit artifacts generated.",
            details={
                "records": len(rows),
                "status_counts": status_counts,
                "csv_path": os.path.abspath(filename_csv),
                "json_path": os.path.abspath(filename_json),
                "csv_sha256": csv_hash,
                "json_sha256": json_hash,
                "s3_location": s3_location,
            },
        )

    except Exception as e:
        logger.log("export_audit", "error", f"Error generating audit report: {e}", level="ERROR")
        raise


if __name__ == "__main__":
    export_audit_report()
