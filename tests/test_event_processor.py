"""Tests for Event Processor."""

import asyncio
from datetime import datetime

import pytest

from src.models.alert import Alert, AlertStatus, AlertSeverity
from src.processing.event_processor import EventProcessor, Deduplicator, PriorityQueue


class TestDeduplicator:
    """Test cases for Deduplicator."""

    @pytest.fixture
    def deduplicator(self):
        return Deduplicator(window_seconds=60)

    @pytest.mark.asyncio
    async def test_first_alert_not_duplicate(self, deduplicator):
        """First alert should not be a duplicate."""
        alert = Alert(
            fingerprint="abc123",
            alertname="TestAlert",
            instance="server1:9100",
        )

        is_dup = await deduplicator.is_duplicate(alert)
        assert not is_dup

    @pytest.mark.asyncio
    async def test_second_alert_is_duplicate(self, deduplicator):
        """Same alert within window should be duplicate."""
        alert = Alert(
            fingerprint="abc123",
            alertname="TestAlert",
            instance="server1:9100",
        )

        await deduplicator.is_duplicate(alert)
        is_dup = await deduplicator.is_duplicate(alert)
        assert is_dup

    @pytest.mark.asyncio
    async def test_different_alert_not_duplicate(self, deduplicator):
        """Different alert should not be duplicate."""
        alert1 = Alert(
            fingerprint="abc123",
            alertname="TestAlert",
            instance="server1:9100",
        )
        alert2 = Alert(
            fingerprint="def456",
            alertname="OtherAlert",
            instance="server2:9100",
        )

        await deduplicator.is_duplicate(alert1)
        is_dup = await deduplicator.is_duplicate(alert2)
        assert not is_dup


class TestPriorityQueue:
    """Test cases for PriorityQueue."""

    @pytest.fixture
    def queue(self):
        return PriorityQueue(max_size=100)

    @pytest.mark.asyncio
    async def test_push_and_pop(self, queue):
        """Test basic push and pop operations."""
        from src.models.incident import Incident

        alert = Alert(severity=AlertSeverity.MEDIUM)
        incident = Incident(alerts=[alert])

        await queue.push(incident)
        assert len(queue) == 1

        result = await queue.pop()
        assert result.id == incident.id
        assert len(queue) == 0

    @pytest.mark.asyncio
    async def test_priority_ordering(self, queue):
        """Higher priority incidents should be popped first."""
        from src.models.incident import Incident

        # Add low priority first
        low_alert = Alert(severity=AlertSeverity.LOW)
        low_incident = Incident(alerts=[low_alert])
        await queue.push(low_incident)

        # Add critical priority second
        critical_alert = Alert(severity=AlertSeverity.CRITICAL)
        critical_incident = Incident(alerts=[critical_alert])
        await queue.push(critical_incident)

        # Critical should come out first
        result = await queue.pop()
        assert result.id == critical_incident.id

    @pytest.mark.asyncio
    async def test_max_size(self, queue):
        """Queue should respect max size."""
        from src.models.incident import Incident

        small_queue = PriorityQueue(max_size=2)

        for i in range(5):
            alert = Alert(severity=AlertSeverity.MEDIUM)
            incident = Incident(alerts=[alert])
            await small_queue.push(incident)

        # Should only have max_size items
        assert len(small_queue) == 2


class TestEventProcessor:
    """Test cases for EventProcessor."""

    @pytest.fixture
    def settings(self):
        """Create mock settings."""
        from src.config import Settings, ProcessingConfig

        settings = Settings()
        settings.processing = ProcessingConfig(
            dedup_window_seconds=60,
            correlation_window_seconds=120,
            max_queue_size=100,
        )
        return settings

    @pytest.fixture
    def processor(self, settings):
        return EventProcessor(settings)

    @pytest.mark.asyncio
    async def test_process_new_alert(self, processor):
        """Processing a new alert should create an incident."""
        alert = Alert(
            fingerprint="abc123",
            alertname="TestAlert",
            instance="server1:9100",
            severity=AlertSeverity.HIGH,
        )

        incident = await processor.process_alert(alert)

        assert incident is not None
        assert len(incident.alerts) == 1
        assert incident.alerts[0].id == alert.id

    @pytest.mark.asyncio
    async def test_process_duplicate_alert(self, processor):
        """Processing a duplicate alert should return None."""
        alert = Alert(
            fingerprint="abc123",
            alertname="TestAlert",
            instance="server1:9100",
        )

        await processor.process_alert(alert)
        result = await processor.process_alert(alert)

        assert result is None

    @pytest.mark.asyncio
    async def test_process_resolved_alert(self, processor):
        """Processing a resolved alert should update incident."""
        # First, create an incident
        firing_alert = Alert(
            fingerprint="abc123",
            alertname="TestAlert",
            instance="server1:9100",
            status=AlertStatus.FIRING,
        )
        incident = await processor.process_alert(firing_alert)

        # Then resolve it
        resolved_alert = Alert(
            fingerprint="abc123",
            alertname="TestAlert",
            instance="server1:9100",
            status=AlertStatus.RESOLVED,
        )
        await processor.process_alert(resolved_alert)

        # Check the incident was updated
        updated = processor.get_incident(incident.id)
        assert updated.alerts[0].status == AlertStatus.RESOLVED

    @pytest.mark.asyncio
    async def test_correlation(self, processor):
        """Related alerts should be correlated into same incident."""
        alert1 = Alert(
            fingerprint="abc123",
            alertname="HighCPU",
            instance="server1:9100",
        )
        alert2 = Alert(
            fingerprint="def456",  # Different fingerprint
            alertname="HighCPU",  # Same alertname
            instance="server1:9100",  # Same instance
        )

        incident1 = await processor.process_alert(alert1)
        incident2 = await processor.process_alert(alert2)

        # Should be the same incident
        assert incident1.id == incident2.id
        assert len(incident1.alerts) == 2
