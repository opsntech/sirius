"""Event processor for alert deduplication, correlation, and incident management."""

import asyncio
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
import heapq

import structlog

from src.config import Settings
from src.models.alert import Alert, AlertSeverity, AlertStatus
from src.models.incident import Incident, IncidentStatus


logger = structlog.get_logger()


class PriorityQueue:
    """Thread-safe priority queue for incidents."""

    # Priority mapping (lower number = higher priority)
    PRIORITY_MAP = {
        AlertSeverity.CRITICAL: 1,
        AlertSeverity.HIGH: 2,
        AlertSeverity.MEDIUM: 3,
        AlertSeverity.LOW: 4,
        AlertSeverity.INFO: 5,
    }

    def __init__(self, max_size: int = 1000):
        self._heap: List[tuple] = []
        self._max_size = max_size
        self._lock = asyncio.Lock()
        self._counter = 0

    async def push(self, incident: Incident):
        """Add an incident to the queue."""
        async with self._lock:
            if len(self._heap) >= self._max_size:
                logger.warning(
                    "Priority queue at max capacity",
                    max_size=self._max_size,
                    dropping_incident=incident.id,
                )
                return

            # Priority based on severity
            primary_alert = incident.primary_alert
            if primary_alert:
                priority = self.PRIORITY_MAP.get(primary_alert.severity, 3)
            else:
                priority = 3

            # Use counter to maintain FIFO order for same priority
            self._counter += 1
            heapq.heappush(self._heap, (priority, self._counter, incident))

    async def pop(self) -> Optional[Incident]:
        """Remove and return the highest priority incident."""
        async with self._lock:
            if self._heap:
                _, _, incident = heapq.heappop(self._heap)
                return incident
            return None

    async def peek(self) -> Optional[Incident]:
        """Return the highest priority incident without removing it."""
        async with self._lock:
            if self._heap:
                _, _, incident = self._heap[0]
                return incident
            return None

    def __len__(self):
        return len(self._heap)


class Deduplicator:
    """Alert deduplication using fingerprints and time windows."""

    def __init__(self, window_seconds: int = 300):
        self._window = timedelta(seconds=window_seconds)
        self._seen: Dict[str, datetime] = {}
        self._lock = asyncio.Lock()

    async def is_duplicate(self, alert: Alert) -> bool:
        """Check if an alert is a duplicate within the time window."""
        async with self._lock:
            key = alert.dedup_key
            now = datetime.utcnow()

            # Clean up old entries
            self._seen = {
                k: v for k, v in self._seen.items()
                if now - v < self._window
            }

            # Check if we've seen this alert
            if key in self._seen:
                logger.debug(
                    "Duplicate alert detected",
                    dedup_key=key,
                    first_seen=self._seen[key].isoformat(),
                )
                return True

            # Record this alert
            self._seen[key] = now
            return False

    async def clear(self):
        """Clear all deduplication state."""
        async with self._lock:
            self._seen.clear()


class Correlator:
    """Alert correlation to group related alerts into incidents."""

    def __init__(self, window_seconds: int = 600):
        self._window = timedelta(seconds=window_seconds)
        self._lock = asyncio.Lock()

    def _get_correlation_key(self, alert: Alert) -> str:
        """Generate a correlation key for grouping alerts."""
        # Correlate by host and alertname
        return f"{alert.host}:{alert.alertname}"

    async def find_matching_incident(
        self,
        alert: Alert,
        open_incidents: Dict[str, Incident],
    ) -> Optional[Incident]:
        """Find an existing incident that this alert should be correlated with."""
        async with self._lock:
            now = datetime.utcnow()
            correlation_key = self._get_correlation_key(alert)

            for incident in open_incidents.values():
                # Skip resolved incidents
                if incident.status == IncidentStatus.RESOLVED:
                    continue

                # Check time window
                if now - incident.detected_at > self._window:
                    continue

                # Check if any alert in the incident has the same correlation key
                for existing_alert in incident.alerts:
                    existing_key = self._get_correlation_key(existing_alert)
                    if existing_key == correlation_key:
                        return incident

                # Also check by affected server
                if alert.host in incident.affected_servers:
                    return incident

            return None


class EventProcessor:
    """
    Main event processor that handles alert ingestion, deduplication,
    correlation, and incident management.
    """

    def __init__(self, settings: Settings):
        self._settings = settings
        self._deduplicator = Deduplicator(
            window_seconds=settings.processing.dedup_window_seconds
        )
        self._correlator = Correlator(
            window_seconds=settings.processing.correlation_window_seconds
        )
        self._priority_queue = PriorityQueue(
            max_size=settings.processing.max_queue_size
        )

        # Incident storage (in-memory for now)
        self._incidents: Dict[str, Incident] = {}
        self._incidents_by_alert: Dict[str, str] = {}  # alert_id -> incident_id

        # Processing state
        self._running = False
        self._process_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()

        # Callbacks for when incidents need AI analysis
        self._analysis_callback = None

    def set_analysis_callback(self, callback):
        """Set callback for incident analysis."""
        self._analysis_callback = callback

    async def start(self):
        """Start the event processor."""
        logger.info("Starting event processor")
        self._running = True
        self._process_task = asyncio.create_task(self._process_loop())

    async def stop(self):
        """Stop the event processor."""
        logger.info("Stopping event processor")
        self._running = False
        if self._process_task:
            self._process_task.cancel()
            try:
                await self._process_task
            except asyncio.CancelledError:
                pass

    async def process_alert(self, alert: Alert) -> Optional[Incident]:
        """
        Process an incoming alert.

        1. Deduplicate
        2. Correlate with existing incidents or create new
        3. Queue for AI analysis
        """
        # Handle resolved alerts
        if alert.status == AlertStatus.RESOLVED:
            return await self._handle_resolved_alert(alert)

        # Deduplicate
        if await self._deduplicator.is_duplicate(alert):
            logger.debug(
                "Alert deduplicated",
                alertname=alert.alertname,
                instance=alert.instance,
            )
            return None

        # Find or create incident
        async with self._lock:
            # Try to correlate with existing incident
            incident = await self._correlator.find_matching_incident(
                alert, self._incidents
            )

            if incident:
                # Add to existing incident
                incident.add_alert(alert)
                self._incidents_by_alert[alert.id] = incident.id
                logger.info(
                    "Alert correlated with existing incident",
                    alert_id=alert.id,
                    alertname=alert.alertname,
                    incident_id=incident.id,
                )
            else:
                # Create new incident
                incident = Incident(
                    alerts=[alert],
                    primary_alert_id=alert.id,
                )
                self._incidents[incident.id] = incident
                self._incidents_by_alert[alert.id] = incident.id
                logger.info(
                    "New incident created",
                    incident_id=incident.id,
                    alertname=alert.alertname,
                    severity=incident.severity.value,
                )

                # Queue for analysis
                await self._priority_queue.push(incident)

        return incident

    async def _handle_resolved_alert(self, alert: Alert) -> Optional[Incident]:
        """Handle a resolved alert by updating the corresponding incident."""
        async with self._lock:
            # Find incident by alert fingerprint
            for incident in self._incidents.values():
                for existing_alert in incident.alerts:
                    if existing_alert.fingerprint == alert.fingerprint:
                        # Update the alert status
                        existing_alert.status = AlertStatus.RESOLVED
                        existing_alert.ends_at = alert.ends_at or datetime.utcnow()

                        # Check if all alerts are resolved
                        all_resolved = all(
                            a.status == AlertStatus.RESOLVED
                            for a in incident.alerts
                        )

                        if all_resolved and incident.status != IncidentStatus.RESOLVED:
                            incident.resolve()
                            logger.info(
                                "Incident auto-resolved",
                                incident_id=incident.id,
                            )

                        return incident

        return None

    async def _process_loop(self):
        """Background loop to process queued incidents."""
        logger.info("Event processor loop started")

        while self._running:
            try:
                # Get next incident from queue
                incident = await self._priority_queue.pop()

                if incident and self._analysis_callback:
                    try:
                        await self._analysis_callback(incident)
                    except Exception as e:
                        logger.error(
                            "Failed to analyze incident",
                            incident_id=incident.id,
                            error=str(e),
                        )

                # Small delay to prevent busy loop
                await asyncio.sleep(0.1)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error in event processor loop", error=str(e))
                await asyncio.sleep(1)

        logger.info("Event processor loop stopped")

    def get_active_incidents(self) -> List[Incident]:
        """Get all active (non-resolved) incidents."""
        return [
            inc for inc in self._incidents.values()
            if inc.status != IncidentStatus.RESOLVED
        ]

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Get an incident by ID."""
        return self._incidents.get(incident_id)

    def get_incident_for_alert(self, alert_id: str) -> Optional[Incident]:
        """Get the incident associated with an alert."""
        incident_id = self._incidents_by_alert.get(alert_id)
        if incident_id:
            return self._incidents.get(incident_id)
        return None

    @property
    def queue_size(self) -> int:
        """Get the current queue size."""
        return len(self._priority_queue)

    @property
    def incident_count(self) -> int:
        """Get the total number of incidents."""
        return len(self._incidents)

    @property
    def active_incident_count(self) -> int:
        """Get the number of active incidents."""
        return len(self.get_active_incidents())
