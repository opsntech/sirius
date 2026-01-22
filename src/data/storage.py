"""Training data storage for ML pipeline.

Provides persistent storage for training examples with support for
querying, filtering, and exporting in various formats.
"""

import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Iterator
import asyncio
from contextlib import contextmanager

import structlog

from src.models.training import TrainingExample, TaskType


logger = structlog.get_logger()


class TrainingDataStorage:
    """
    Persistent storage for training examples.

    Uses SQLite for metadata and JSONL files for full examples.
    Supports querying, filtering, and batch export.
    """

    def __init__(self, storage_path: str):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)

        self.db_path = self.storage_path / "training_data.db"
        self.examples_path = self.storage_path / "examples"
        self.examples_path.mkdir(exist_ok=True)

        self._init_db()

    def _init_db(self):
        """Initialize SQLite database schema."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS examples (
                    example_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    task_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    alert_type TEXT,
                    severity TEXT,
                    environment TEXT,
                    quality_score REAL,
                    resolution_success INTEGER,
                    human_approved INTEGER,
                    is_positive_example INTEGER,
                    file_path TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_incident_id ON examples(incident_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_task_type ON examples(task_type)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_quality_score ON examples(quality_score)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_alert_type ON examples(alert_type)
            """)

            conn.commit()

    @contextmanager
    def _get_connection(self):
        """Get a database connection with context management."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    async def store(self, example: TrainingExample) -> str:
        """Store a training example."""
        # Write full example to JSONL file (partitioned by date)
        date_str = datetime.utcnow().strftime("%Y-%m-%d")
        file_path = self.examples_path / f"{date_str}.jsonl"

        def _write():
            with open(file_path, "a") as f:
                f.write(example.to_jsonl() + "\n")

            # Store metadata in SQLite
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO examples (
                        example_id, incident_id, task_type, timestamp,
                        alert_type, severity, environment, quality_score,
                        resolution_success, human_approved, is_positive_example,
                        file_path
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    example.example_id,
                    example.incident_id,
                    example.task_type,
                    example.timestamp,
                    example.metadata.alert_type,
                    example.metadata.severity,
                    example.metadata.environment,
                    example.outcome.quality_score,
                    1 if example.outcome.resolution_success else 0 if example.outcome.resolution_success is False else None,
                    1 if example.outcome.human_approved else 0 if example.outcome.human_approved is False else None,
                    1 if example.outcome.is_positive_example else 0,
                    str(file_path),
                ))
                conn.commit()

        await asyncio.to_thread(_write)

        logger.debug(
            "Stored training example",
            example_id=example.example_id,
            task_type=example.task_type,
            quality_score=example.outcome.quality_score,
        )

        return example.example_id

    async def get(self, example_id: str) -> Optional[TrainingExample]:
        """Retrieve a training example by ID."""
        def _read():
            with self._get_connection() as conn:
                row = conn.execute(
                    "SELECT file_path FROM examples WHERE example_id = ?",
                    (example_id,)
                ).fetchone()

                if not row:
                    return None

                file_path = Path(row["file_path"])
                if not file_path.exists():
                    return None

                # Search through JSONL file for the example
                with open(file_path) as f:
                    for line in f:
                        data = json.loads(line)
                        if data.get("example_id") == example_id:
                            return self._dict_to_example(data)

            return None

        return await asyncio.to_thread(_read)

    async def query(
        self,
        task_type: Optional[str] = None,
        min_quality_score: float = 0.0,
        only_successful: bool = False,
        only_positive: bool = False,
        alert_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 1000,
        offset: int = 0,
    ) -> List[TrainingExample]:
        """Query training examples with filters."""
        def _query():
            conditions = ["1=1"]
            params = []

            if task_type:
                conditions.append("task_type = ?")
                params.append(task_type)

            if min_quality_score > 0:
                conditions.append("quality_score >= ?")
                params.append(min_quality_score)

            if only_successful:
                conditions.append("resolution_success = 1")

            if only_positive:
                conditions.append("is_positive_example = 1")

            if alert_type:
                conditions.append("alert_type = ?")
                params.append(alert_type)

            if severity:
                conditions.append("severity = ?")
                params.append(severity)

            query = f"""
                SELECT example_id, file_path FROM examples
                WHERE {' AND '.join(conditions)}
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
            """
            params.extend([limit, offset])

            examples = []
            with self._get_connection() as conn:
                rows = conn.execute(query, params).fetchall()

                # Group by file to minimize file reads
                files_to_ids: Dict[str, List[str]] = {}
                for row in rows:
                    fp = row["file_path"]
                    if fp not in files_to_ids:
                        files_to_ids[fp] = []
                    files_to_ids[fp].append(row["example_id"])

                # Read examples from files
                for file_path, ids in files_to_ids.items():
                    if not Path(file_path).exists():
                        continue
                    ids_set = set(ids)
                    with open(file_path) as f:
                        for line in f:
                            data = json.loads(line)
                            if data.get("example_id") in ids_set:
                                examples.append(self._dict_to_example(data))

            return examples

        return await asyncio.to_thread(_query)

    async def count(
        self,
        task_type: Optional[str] = None,
        min_quality_score: float = 0.0,
    ) -> int:
        """Count examples matching criteria."""
        def _count():
            conditions = ["1=1"]
            params = []

            if task_type:
                conditions.append("task_type = ?")
                params.append(task_type)

            if min_quality_score > 0:
                conditions.append("quality_score >= ?")
                params.append(min_quality_score)

            with self._get_connection() as conn:
                result = conn.execute(
                    f"SELECT COUNT(*) as cnt FROM examples WHERE {' AND '.join(conditions)}",
                    params
                ).fetchone()
                return result["cnt"]

        return await asyncio.to_thread(_count)

    async def get_stats(self) -> Dict:
        """Get storage statistics."""
        def _stats():
            with self._get_connection() as conn:
                total = conn.execute("SELECT COUNT(*) as cnt FROM examples").fetchone()["cnt"]

                by_task = {}
                for row in conn.execute(
                    "SELECT task_type, COUNT(*) as cnt FROM examples GROUP BY task_type"
                ).fetchall():
                    by_task[row["task_type"]] = row["cnt"]

                by_severity = {}
                for row in conn.execute(
                    "SELECT severity, COUNT(*) as cnt FROM examples GROUP BY severity"
                ).fetchall():
                    by_severity[row["severity"]] = row["cnt"]

                avg_quality = conn.execute(
                    "SELECT AVG(quality_score) as avg FROM examples"
                ).fetchone()["avg"]

                positive_count = conn.execute(
                    "SELECT COUNT(*) as cnt FROM examples WHERE is_positive_example = 1"
                ).fetchone()["cnt"]

                return {
                    "total_examples": total,
                    "by_task_type": by_task,
                    "by_severity": by_severity,
                    "average_quality_score": avg_quality or 0,
                    "positive_examples": positive_count,
                    "positive_rate": positive_count / total if total > 0 else 0,
                }

        return await asyncio.to_thread(_stats)

    async def export_jsonl(
        self,
        output_path: str,
        task_type: Optional[str] = None,
        min_quality_score: float = 0.6,
        only_positive: bool = True,
        include_system_prompt: bool = True,
    ) -> int:
        """Export examples to JSONL format for training."""
        from src.models.training import TASK_SYSTEM_PROMPTS

        examples = await self.query(
            task_type=task_type,
            min_quality_score=min_quality_score,
            only_positive=only_positive,
            limit=100000,
        )

        def _export():
            count = 0
            with open(output_path, "w") as f:
                for example in examples:
                    if include_system_prompt:
                        system_prompt = TASK_SYSTEM_PROMPTS.get(
                            example.task_type,
                            TASK_SYSTEM_PROMPTS[TaskType.END_TO_END.value]
                        )
                        formatted = example.to_instruction_format(system_prompt)
                    else:
                        formatted = example.to_dict()

                    f.write(json.dumps(formatted) + "\n")
                    count += 1

            return count

        count = await asyncio.to_thread(_export)

        logger.info(
            "Exported training data",
            output_path=output_path,
            example_count=count,
            task_type=task_type,
        )

        return count

    def _dict_to_example(self, data: Dict) -> TrainingExample:
        """Convert dictionary to TrainingExample."""
        from src.models.training import (
            InputContext, AlertData, OutcomeLabels, ExampleMetadata,
            InvestigationStepData, SimilarIncidentSummary, ServerInfo
        )

        # Reconstruct InputContext
        alert_data = data.get("input_context", {}).get("alert", {})
        alert = AlertData(**alert_data) if alert_data else AlertData(
            fingerprint="", alertname="", severity="", status="",
            instance="", job="", summary="", description="",
            labels={}, annotations={}
        )

        input_ctx_data = data.get("input_context", {})
        investigation_steps = [
            InvestigationStepData(**s)
            for s in input_ctx_data.get("investigation_steps", [])
        ]
        similar_incidents = [
            SimilarIncidentSummary(**s)
            for s in input_ctx_data.get("similar_incidents", [])
        ]
        server_info = None
        if input_ctx_data.get("server_info"):
            server_info = ServerInfo(**input_ctx_data["server_info"])

        input_context = InputContext(
            alert=alert,
            investigation_steps=investigation_steps,
            similar_incidents=similar_incidents,
            server_info=server_info,
            incident_age_seconds=input_ctx_data.get("incident_age_seconds", 0),
        )

        # Reconstruct OutcomeLabels
        outcome_data = data.get("outcome", {})
        outcome = OutcomeLabels(**outcome_data)

        # Reconstruct Metadata
        metadata_data = data.get("metadata", {})
        metadata = ExampleMetadata(**metadata_data) if metadata_data else ExampleMetadata(
            alert_type="unknown", severity="unknown"
        )

        return TrainingExample(
            example_id=data.get("example_id", ""),
            incident_id=data.get("incident_id", ""),
            timestamp=data.get("timestamp", ""),
            input_context=input_context,
            task_type=data.get("task_type", TaskType.TRIAGE.value),
            expected_output=data.get("expected_output", {}),
            outcome=outcome,
            metadata=metadata,
        )


# Global storage instance
_storage: Optional[TrainingDataStorage] = None


def get_storage(storage_path: str = "/var/lib/sirius/training_data") -> TrainingDataStorage:
    """Get the global storage instance."""
    global _storage
    if _storage is None:
        _storage = TrainingDataStorage(storage_path)
    return _storage
