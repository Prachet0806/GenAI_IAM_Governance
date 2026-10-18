#reports/export_audit.py
import csv
import json
import os
import hashlib
import uuid
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
    run_id = str(uuid.uuid4())
    report_dir = "reports"
    os.makedirs(report_dir, exist_ok=True)
    filename_csv = f"{report_dir}/access_certification_{date_part}_{run_id}.csv"
    filename_json = f"{report_dir}/access_certification_{date_part}_{run_id}.json"
    filename_manifest = f"{report_dir}/access_certification_{date_part}_{run_id}.manifest.json"

    logger.log(
        "export_audit",
        "start",
        f"Generating Audit Artifacts ({filename_csv}, {filename_json})",
        details={"db": config.redact_db_url()},
    )

    try:
        with db.get_connection() as conn:
            rows = repo.fetch_reviews_for_export(conn)

        if not rows:
            raise RuntimeError("No access review records to export (blocking empty artifact).")

        # Integrity: counts by status (index 5 per fetch_reviews_for_export contract)
        status_counts = {}
        for row in rows:
            if len(row) != 15:
                raise RuntimeError(f"Unexpected export row width {len(row)}; expected 15.")
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
                "Remediated At", "AI Source", "AI Model", "AI Prompt Version", "AI Generated At"
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
                "ai_source": r[11],
                "ai_model": r[12],
                "ai_prompt_version": r[13],
                "ai_generated_at": r[14],
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

        manifest = {
            "export_run_id": run_id, "generated_at": ts.isoformat(), "record_count": len(rows),
            "schema_version": config.SCHEMA_VERSION,
            "artifacts": {"csv": {"path": os.path.basename(filename_csv), "sha256": csv_hash},
                          "json": {"path": os.path.basename(filename_json), "sha256": json_hash}},
        }
        with open(filename_manifest, "w", encoding="utf-8") as mf:
            json.dump(manifest, mf, ensure_ascii=False, indent=2, sort_keys=True)
        with open(filename_manifest, "rb") as mf:
            manifest_hash = _sha256_bytes(mf.read())

        # Optional S3 upload
        audit_bucket = os.getenv("AUDIT_S3_BUCKET")
        local_only = config.is_local_only()
        if audit_bucket and not local_only:
            from botocore.config import Config as BotoConfig
            s3 = boto3.client(
                "s3",
                region_name=config.get_aws_region(),
                config=BotoConfig(connect_timeout=10, read_timeout=30, retries={"max_attempts": 3}),
            )
            prefix = (os.getenv("AUDIT_S3_PREFIX", "") or "").strip().strip("/")
            # Guard against path traversal in prefix
            if ".." in prefix.split("/"):
                raise ValueError("Invalid AUDIT_S3_PREFIX: must not contain '..'")
            base_path = f"{prefix}/access_reviews/{date_part}" if prefix else f"access_reviews/{date_part}"
            export_path = f"{base_path}/{run_id}"
            s3_csv_key = f"{export_path}/access_certification.csv"
            s3_json_key = f"{export_path}/access_certification.json"

            common_meta = {
                "generated_at": ts.isoformat(),
                "record_count": str(len(rows)),
                "csv_sha256": csv_hash,
                "json_sha256": json_hash,
            }

            s3.upload_file(
                filename_csv,
                audit_bucket,
                s3_csv_key,
                ExtraArgs={
                    "Metadata": common_meta,
                    "ContentType": "text/csv",
                    "ServerSideEncryption": "AES256",
                },
            )
            s3.upload_file(
                filename_json,
                audit_bucket,
                s3_json_key,
                ExtraArgs={
                    "Metadata": common_meta,
                    "ContentType": "application/json",
                    "ServerSideEncryption": "AES256",
                },
            )
            s3.upload_file(filename_manifest, audit_bucket, f"{export_path}/manifest.json",
                           ExtraArgs={"Metadata": {"manifest_sha256": manifest_hash},
                                      "ContentType": "application/json", "ServerSideEncryption": "AES256"})
            s3_location = f"s3://{audit_bucket}/{export_path}"
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
                "manifest_path": os.path.abspath(filename_manifest),
                "csv_sha256": csv_hash,
                "json_sha256": json_hash,
                "manifest_sha256": manifest_hash,
                "s3_location": s3_location,
            },
        )
        try:
            import uuid
            with db.get_connection() as _audit_conn:
                repo.insert_audit_log(
                    _audit_conn, str(uuid.uuid4()), datetime.now(timezone.utc), "INFO",
                    "export_audit", "success", "Audit artifacts generated.",
                    details={"records": len(rows), "status_counts": status_counts,
                             "csv_sha256": csv_hash, "json_sha256": json_hash,
                             "manifest_sha256": manifest_hash, "export_run_id": run_id,
                             "s3_location": s3_location},
                )
        except Exception as e:
            logger.log("export_audit", "warn", f"audit log write failed: {e}", level="WARN")

    except Exception as e:
        logger.log("export_audit", "error", f"Error generating audit report: {e}", level="ERROR")
        raise

    return {"export_run_id": run_id, "csv": filename_csv, "json": filename_json,
            "manifest": filename_manifest, "s3_location": s3_location}


if __name__ == "__main__":
    export_audit_report()
