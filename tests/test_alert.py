"""Tests for Alert model."""

import json
from datetime import datetime
from pathlib import Path

import pytest

from src.models.alert import Alert, AlertStatus, AlertSeverity


class TestAlert:
    """Test cases for Alert model."""

    def test_create_alert(self):
        """Test creating an alert with default values."""
        alert = Alert(
            alertname="TestAlert",
            instance="server1:9100",
            severity=AlertSeverity.HIGH,
            summary="Test summary",
        )

        assert alert.alertname == "TestAlert"
        assert alert.instance == "server1:9100"
        assert alert.severity == AlertSeverity.HIGH
        assert alert.status == AlertStatus.FIRING
        assert alert.id is not None

    def test_alert_host_property(self):
        """Test host extraction from instance."""
        alert = Alert(instance="server1.example.com:9100")
        assert alert.host == "server1.example.com"

        alert2 = Alert(instance="192.168.1.10:9100")
        assert alert2.host == "192.168.1.10"

        alert3 = Alert(instance="server1")
        assert alert3.host == "server1"

    def test_alert_dedup_key(self):
        """Test deduplication key generation."""
        alert = Alert(
            fingerprint="abc123",
            alertname="TestAlert",
            instance="server1:9100",
        )
        assert alert.dedup_key == "abc123"

        alert2 = Alert(
            alertname="TestAlert",
            instance="server1:9100",
        )
        assert alert2.dedup_key == "TestAlert:server1:9100"

    def test_from_prometheus(self):
        """Test creating alert from Prometheus payload."""
        payload = {
            "status": "firing",
            "labels": {
                "alertname": "HighCPUUsage",
                "severity": "critical",
                "instance": "server1:9100",
                "job": "node",
            },
            "annotations": {
                "summary": "High CPU usage detected",
                "description": "CPU at 95%",
            },
            "startsAt": "2024-01-15T10:30:00Z",
            "fingerprint": "abc123",
        }

        alert = Alert.from_prometheus(payload)

        assert alert.alertname == "HighCPUUsage"
        assert alert.severity == AlertSeverity.CRITICAL
        assert alert.instance == "server1:9100"
        assert alert.job == "node"
        assert alert.summary == "High CPU usage detected"
        assert alert.fingerprint == "abc123"
        assert alert.status == AlertStatus.FIRING

    def test_from_prometheus_resolved(self):
        """Test creating resolved alert from Prometheus payload."""
        payload = {
            "status": "resolved",
            "labels": {
                "alertname": "HighCPUUsage",
                "instance": "server1:9100",
            },
            "annotations": {},
            "fingerprint": "abc123",
        }

        alert = Alert.from_prometheus(payload)
        assert alert.status == AlertStatus.RESOLVED

    def test_alert_to_dict(self):
        """Test alert serialization."""
        alert = Alert(
            alertname="TestAlert",
            instance="server1:9100",
            severity=AlertSeverity.HIGH,
            summary="Test summary",
        )

        data = alert.to_dict()

        assert data["alertname"] == "TestAlert"
        assert data["instance"] == "server1:9100"
        assert data["severity"] == "high"
        assert data["summary"] == "Test summary"
        assert "id" in data
        assert "received_at" in data

    def test_from_sample_fixture(self):
        """Test parsing the sample alert fixture."""
        fixture_path = Path(__file__).parent / "fixtures" / "sample_alert.json"

        with open(fixture_path) as f:
            payload = json.load(f)

        # Parse each alert in the payload
        for alert_data in payload["alerts"]:
            alert = Alert.from_prometheus(alert_data)

            assert alert.alertname == "HighCPUUsage"
            assert alert.severity == AlertSeverity.CRITICAL
            assert alert.host == "web-server-1.example.com"
            assert alert.job == "node"
            assert "CPU usage > 90%" in alert.summary
