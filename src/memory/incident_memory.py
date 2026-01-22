"""Incident memory for pattern recognition using vector similarity.

Stores embeddings of resolved incidents and enables similarity search
to find relevant past incidents for new alerts.
"""

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import asyncio

import structlog

from src.models.incident import Incident, IncidentStatus
from src.models.alert import Alert


logger = structlog.get_logger()


@dataclass
class SimilarIncident:
    """A similar past incident found via memory search."""

    incident_id: str
    similarity: float
    root_cause: str
    resolution_type: str
    actions_taken: List[str]
    mttr_seconds: Optional[int] = None
    metadata: Dict[str, Any] = None

    def to_dict(self) -> Dict:
        return {
            "incident_id": self.incident_id,
            "similarity_score": self.similarity,
            "root_cause": self.root_cause,
            "resolution_type": self.resolution_type,
            "actions_taken": self.actions_taken,
            "mttr_seconds": self.mttr_seconds,
        }


@dataclass
class IncidentRecord:
    """Stored incident record for memory."""

    incident_id: str
    alert_type: str
    host: str
    service: str
    root_cause: str
    resolution_type: str
    actions_taken: List[str]
    success: bool
    mttr_seconds: Optional[int]
    timestamp: str
    embedding_text: str
    labels: Dict[str, str]


class IncidentMemory:
    """
    Stores and retrieves incident patterns using vector similarity.

    This implementation uses a simple text-based similarity approach
    that can be upgraded to use ChromaDB or other vector DBs.
    """

    def __init__(
        self,
        storage_path: str = "/var/lib/sirius/memory",
        similarity_threshold: float = 0.75,
        max_similar: int = 5,
        use_vector_db: bool = False,
    ):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)

        self.similarity_threshold = similarity_threshold
        self.max_similar = max_similar
        self.use_vector_db = use_vector_db

        self._records_file = self.storage_path / "incident_records.jsonl"
        self._records_cache: Dict[str, IncidentRecord] = {}
        self._lock = asyncio.Lock()

        # Try to use ChromaDB if available
        self._chroma_client = None
        self._collection = None

        if use_vector_db:
            self._init_vector_db()

        # Load existing records into cache
        self._load_records()

    def _init_vector_db(self):
        """Initialize ChromaDB if available."""
        try:
            import chromadb
            from chromadb.config import Settings

            self._chroma_client = chromadb.Client(Settings(
                chroma_db_impl="duckdb+parquet",
                persist_directory=str(self.storage_path / "chroma"),
                anonymized_telemetry=False,
            ))

            self._collection = self._chroma_client.get_or_create_collection(
                name="incidents",
                metadata={"hnsw:space": "cosine"}
            )

            logger.info("Initialized ChromaDB for incident memory")

        except ImportError:
            logger.warning(
                "ChromaDB not available, falling back to text similarity"
            )
            self.use_vector_db = False
        except Exception as e:
            logger.error(f"Failed to initialize ChromaDB: {e}")
            self.use_vector_db = False

    def _load_records(self):
        """Load existing records into memory cache."""
        if not self._records_file.exists():
            return

        try:
            with open(self._records_file) as f:
                for line in f:
                    data = json.loads(line.strip())
                    record = IncidentRecord(
                        incident_id=data["incident_id"],
                        alert_type=data["alert_type"],
                        host=data["host"],
                        service=data["service"],
                        root_cause=data["root_cause"],
                        resolution_type=data["resolution_type"],
                        actions_taken=data["actions_taken"],
                        success=data["success"],
                        mttr_seconds=data.get("mttr_seconds"),
                        timestamp=data["timestamp"],
                        embedding_text=data["embedding_text"],
                        labels=data.get("labels", {}),
                    )
                    self._records_cache[record.incident_id] = record

            logger.info(
                "Loaded incident records into memory",
                count=len(self._records_cache),
            )
        except Exception as e:
            logger.error(f"Failed to load incident records: {e}")

    def _create_embedding_text(
        self,
        incident: Incident,
        root_cause: str,
        resolution_type: str,
    ) -> str:
        """Create text for embedding from incident data."""
        primary_alert = incident.primary_alert
        if not primary_alert:
            return ""

        parts = [
            f"Alert: {primary_alert.alertname}",
            f"Severity: {primary_alert.severity.value}",
            f"Service: {primary_alert.job}",
            f"Summary: {primary_alert.summary}",
            f"Description: {primary_alert.description}",
            f"Root Cause: {root_cause}",
            f"Resolution: {resolution_type}",
        ]

        # Add relevant labels
        for key in ["environment", "cluster", "namespace", "app"]:
            if key in primary_alert.labels:
                parts.append(f"{key}: {primary_alert.labels[key]}")

        return " | ".join(parts)

    def _create_query_text(self, incident: Incident) -> str:
        """Create query text from a new incident."""
        primary_alert = incident.primary_alert
        if not primary_alert:
            return ""

        parts = [
            f"Alert: {primary_alert.alertname}",
            f"Severity: {primary_alert.severity.value}",
            f"Service: {primary_alert.job}",
            f"Summary: {primary_alert.summary}",
            f"Description: {primary_alert.description}",
        ]

        for key in ["environment", "cluster", "namespace", "app"]:
            if key in primary_alert.labels:
                parts.append(f"{key}: {primary_alert.labels[key]}")

        return " | ".join(parts)

    def _calculate_text_similarity(self, text1: str, text2: str) -> float:
        """Calculate simple text similarity using Jaccard index."""
        if not text1 or not text2:
            return 0.0

        # Tokenize
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())

        # Jaccard similarity
        intersection = len(words1 & words2)
        union = len(words1 | words2)

        if union == 0:
            return 0.0

        return intersection / union

    async def store_incident(
        self,
        incident: Incident,
        root_cause: str,
        resolution_type: str,
        actions_taken: List[str],
        success: bool,
        mttr_seconds: Optional[int] = None,
    ):
        """Store a resolved incident for future pattern matching."""
        async with self._lock:
            primary_alert = incident.primary_alert
            if not primary_alert:
                return

            embedding_text = self._create_embedding_text(
                incident, root_cause, resolution_type
            )

            record = IncidentRecord(
                incident_id=incident.id,
                alert_type=primary_alert.alertname,
                host=primary_alert.host,
                service=primary_alert.job or "unknown",
                root_cause=root_cause,
                resolution_type=resolution_type,
                actions_taken=actions_taken,
                success=success,
                mttr_seconds=mttr_seconds,
                timestamp=datetime.utcnow().isoformat(),
                embedding_text=embedding_text,
                labels=primary_alert.labels,
            )

            # Store in cache
            self._records_cache[incident.id] = record

            # Persist to file
            def _write():
                with open(self._records_file, "a") as f:
                    f.write(json.dumps({
                        "incident_id": record.incident_id,
                        "alert_type": record.alert_type,
                        "host": record.host,
                        "service": record.service,
                        "root_cause": record.root_cause,
                        "resolution_type": record.resolution_type,
                        "actions_taken": record.actions_taken,
                        "success": record.success,
                        "mttr_seconds": record.mttr_seconds,
                        "timestamp": record.timestamp,
                        "embedding_text": record.embedding_text,
                        "labels": record.labels,
                    }) + "\n")

            await asyncio.to_thread(_write)

            # Store in vector DB if available
            if self.use_vector_db and self._collection:
                try:
                    self._collection.add(
                        ids=[incident.id],
                        documents=[embedding_text],
                        metadatas=[{
                            "alert_type": record.alert_type,
                            "root_cause": root_cause,
                            "resolution_type": resolution_type,
                            "success": success,
                            "mttr_seconds": mttr_seconds or 0,
                        }]
                    )
                except Exception as e:
                    logger.error(f"Failed to store in vector DB: {e}")

            logger.info(
                "Stored incident in memory",
                incident_id=incident.id,
                alert_type=primary_alert.alertname,
                success=success,
            )

    async def find_similar(
        self,
        incident: Incident,
        limit: Optional[int] = None,
    ) -> List[SimilarIncident]:
        """Find similar past incidents."""
        limit = limit or self.max_similar
        primary_alert = incident.primary_alert

        if not primary_alert:
            return []

        query_text = self._create_query_text(incident)

        if self.use_vector_db and self._collection:
            return await self._find_similar_vector(query_text, limit)
        else:
            return await self._find_similar_text(incident, query_text, limit)

    async def _find_similar_vector(
        self,
        query_text: str,
        limit: int,
    ) -> List[SimilarIncident]:
        """Find similar incidents using vector DB."""
        try:
            results = self._collection.query(
                query_texts=[query_text],
                n_results=limit,
                where={"success": True}
            )

            similar = []
            if results and results["ids"] and results["ids"][0]:
                for i, id in enumerate(results["ids"][0]):
                    distance = results["distances"][0][i] if results["distances"] else 0
                    meta = results["metadatas"][0][i] if results["metadatas"] else {}

                    # Get full record from cache
                    record = self._records_cache.get(id)
                    actions = record.actions_taken if record else []

                    similarity = 1 - distance  # Convert distance to similarity

                    if similarity >= self.similarity_threshold:
                        similar.append(SimilarIncident(
                            incident_id=id,
                            similarity=similarity,
                            root_cause=meta.get("root_cause", ""),
                            resolution_type=meta.get("resolution_type", ""),
                            actions_taken=actions,
                            mttr_seconds=meta.get("mttr_seconds"),
                        ))

            return similar

        except Exception as e:
            logger.error(f"Vector similarity search failed: {e}")
            return []

    async def _find_similar_text(
        self,
        incident: Incident,
        query_text: str,
        limit: int,
    ) -> List[SimilarIncident]:
        """Find similar incidents using text similarity."""
        primary_alert = incident.primary_alert
        if not primary_alert:
            return []

        similar = []

        for record in self._records_cache.values():
            # Skip failed resolutions
            if not record.success:
                continue

            # Calculate similarity
            similarity = self._calculate_text_similarity(
                query_text,
                record.embedding_text
            )

            # Boost similarity for same alert type
            if record.alert_type == primary_alert.alertname:
                similarity = min(1.0, similarity + 0.2)

            # Boost for same service
            if record.service == primary_alert.job:
                similarity = min(1.0, similarity + 0.1)

            if similarity >= self.similarity_threshold:
                similar.append(SimilarIncident(
                    incident_id=record.incident_id,
                    similarity=similarity,
                    root_cause=record.root_cause,
                    resolution_type=record.resolution_type,
                    actions_taken=record.actions_taken,
                    mttr_seconds=record.mttr_seconds,
                ))

        # Sort by similarity and limit
        similar.sort(key=lambda x: x.similarity, reverse=True)
        return similar[:limit]

    async def get_stats(self) -> Dict:
        """Get memory statistics."""
        total = len(self._records_cache)
        successful = sum(1 for r in self._records_cache.values() if r.success)

        alert_types = {}
        for r in self._records_cache.values():
            alert_types[r.alert_type] = alert_types.get(r.alert_type, 0) + 1

        return {
            "total_incidents": total,
            "successful_resolutions": successful,
            "success_rate": successful / total if total > 0 else 0,
            "alert_types": alert_types,
            "using_vector_db": self.use_vector_db,
        }

    async def clear(self):
        """Clear all memory (use with caution)."""
        async with self._lock:
            self._records_cache.clear()

            if self._records_file.exists():
                self._records_file.unlink()

            if self.use_vector_db and self._collection:
                try:
                    self._chroma_client.delete_collection("incidents")
                    self._collection = self._chroma_client.create_collection(
                        name="incidents"
                    )
                except:
                    pass

            logger.warning("Cleared incident memory")


# Global memory instance
_memory: Optional[IncidentMemory] = None


def get_memory(
    storage_path: str = "/var/lib/sirius/memory",
    similarity_threshold: float = 0.75,
    use_vector_db: bool = False,
) -> IncidentMemory:
    """Get the global memory instance."""
    global _memory
    if _memory is None:
        _memory = IncidentMemory(
            storage_path=storage_path,
            similarity_threshold=similarity_threshold,
            use_vector_db=use_vector_db,
        )
    return _memory
