"""
Real-Time & Replay Passive Inference Streaming Pipeline for UniDetect (Phase 7)
"""

import logging
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import numpy as np

from src.features.correlator import LogCorrelator
from src.features.schema import FEATURE_COLUMNS, NUM_FEATURES
from src.features.vector_assembler import FeatureVectorAssembler
from src.features.window_aggregator import WindowAggregator
from src.inference.alert import AlertEvent
from src.inference.contract import FeatureContractValidationError
from src.inference.detector import ThreatDetector
from src.ingestion.live_pipeline import LiveZeekPipeline
from src.ingestion.zeek_reader import load_zeek_logs
from src.models.flow_record import FlowRecord, normalize_conn_record

logger = logging.getLogger(__name__)

DEFAULT_MODEL_DIR = Path(__file__).resolve().parent.parent.parent / "models" / "phase6e"


class RealtimeInferencePipeline:
    """
    Connects the passive Zeek ingestion pipeline to the frozen Phase 6E ML inference layer.
    Processes network connection flows in strict chronological order, correlations with
    auxiliary event logs (DNS, SSL, Weird, QUIC), maintains causal sliding windows,
    assembles the 78-dimensional feature vector, and emits standardized AlertEvent objects.
    """

    def __init__(
        self,
        model_dir: Optional[Union[str, Path]] = None,
        detector: Optional[ThreatDetector] = None,
    ) -> None:
        if detector is not None:
            self.detector = detector
        else:
            m_dir = Path(model_dir) if model_dir is not None else DEFAULT_MODEL_DIR
            self.detector = ThreatDetector.from_artifact_dir(m_dir)

        self.correlator = LogCorrelator()
        self.window_aggregator = WindowAggregator(flows=[], correlator=self.correlator)
        self.assembler = FeatureVectorAssembler(
            correlator=self.correlator,
            window_aggregator=self.window_aggregator,
        )

        # Performance and Telemetry Counters
        self.total_flows_processed = 0
        self.threats_detected = 0
        self.abstained_reviews = 0
        self.benign_count = 0
        self.inference_errors = 0
        self.latency_records_ms: List[float] = []

    def reset_state(self) -> None:
        """Resets correlator, sliding windows, and performance counters."""
        self.correlator = LogCorrelator()
        self.window_aggregator = WindowAggregator(flows=[], correlator=self.correlator)
        self.assembler = FeatureVectorAssembler(
            correlator=self.correlator,
            window_aggregator=self.window_aggregator,
        )
        self.total_flows_processed = 0
        self.threats_detected = 0
        self.abstained_reviews = 0
        self.benign_count = 0
        self.inference_errors = 0
        self.latency_records_ms.clear()

    def ingest_auxiliary_records(
        self,
        log_name: str,
        records: List[Dict[str, Any]],
    ) -> None:
        """Ingests and indexes auxiliary event records (DNS, SSL, Weird, QUIC) into the correlator."""
        self.correlator.index_all({log_name: records})

    def process_flow(
        self,
        flow: Union[FlowRecord, Dict[str, Any]],
    ) -> AlertEvent:
        """
        Executes real-time threat inference on a single connection flow record.

        Steps:
        1. Normalizes flow to FlowRecord.
        2. Computes causal sliding window features over [t - lookback, t].
        3. Appends flow to window history.
        4. Assembles 78-dimensional float vector.
        5. Runs calibrated ML inference and applies decision policy.
        6. Constructs and returns standardized AlertEvent.
        """
        t_start = time.perf_counter()

        if not isinstance(flow, FlowRecord):
            flow_obj = normalize_conn_record(flow)
        else:
            flow_obj = flow

        # 1. Ensure Causal Window History Updates
        self.window_aggregator.add_flow(flow_obj)

        # 2. Assemble 78D Feature Vector
        try:
            feat_vec = self.assembler.assemble_for_flow(flow_obj)
            verdict = self.detector.predict_single(feat_vec)
            t_elapsed_ms = (time.perf_counter() - t_start) * 1000.0

            alert = AlertEvent.create(
                flow_uid=flow_obj.uid,
                timestamp=flow_obj.timestamp,
                source_ip=flow_obj.source.ip,
                destination_ip=flow_obj.destination.ip,
                source_port=flow_obj.source.port,
                destination_port=flow_obj.destination.port,
                protocol=flow_obj.network.protocol,
                predicted_class_id=verdict["predicted_class_id"],
                predicted_label=verdict["predicted_label"],
                confidence=verdict["confidence"],
                probabilities=verdict["probabilities"],
                abstained=verdict["abstained"],
                decision=verdict["decision"],
                model_version=verdict["model_version"],
                schema_version=verdict["schema_version"],
                processing_time_ms=t_elapsed_ms,
                metadata={
                    "duration": flow_obj.metrics.duration,
                    "orig_bytes": flow_obj.metrics.orig_bytes,
                    "resp_bytes": flow_obj.metrics.resp_bytes,
                    "total_bytes": flow_obj.metrics.total_bytes,
                    "conn_state": flow_obj.connection_state,
                },
            )

            # Update Telemetry Stats
            self.total_flows_processed += 1
            self.latency_records_ms.append(t_elapsed_ms)

            if alert.abstained:
                self.abstained_reviews += 1
            elif alert.predicted_label == "BENIGN":
                self.benign_count += 1
            else:
                self.threats_detected += 1

            return alert

        except Exception as e:
            self.inference_errors += 1
            t_elapsed_ms = (time.perf_counter() - t_start) * 1000.0
            logger.error(f"Inference pipeline error on flow {flow_obj.uid}: {e}")

            # Return Safe Error Alert (Fail-Safe)
            return AlertEvent.create(
                flow_uid=flow_obj.uid,
                timestamp=flow_obj.timestamp,
                source_ip=flow_obj.source.ip,
                destination_ip=flow_obj.destination.ip,
                source_port=flow_obj.source.port,
                destination_port=flow_obj.destination.port,
                protocol=flow_obj.network.protocol,
                predicted_class_id=-1,
                predicted_label="UNKNOWN",
                confidence=0.0,
                probabilities={},
                abstained=True,
                decision="INFERENCE_ERROR",
                model_version=self.detector.model_version,
                schema_version=self.detector.schema_version,
                processing_time_ms=t_elapsed_ms,
                metadata={"error": str(e)},
            )

    def process_log_batch(
        self,
        log_data: Dict[str, List[Any]],
    ) -> List[AlertEvent]:
        """
        Processes a heterogeneous batch of Zeek logs.
        Indexes all auxiliary logs first, then processes conn flows chronologically.
        """
        # 1. Index auxiliary records
        aux_data = {k: v for k, v in log_data.items() if k != "conn"}
        self.correlator.index_all(aux_data)

        # 2. Extract and sort connection records chronologically
        raw_flows = log_data.get("conn", [])
        norm_flows: List[FlowRecord] = []
        for f in raw_flows:
            if isinstance(f, FlowRecord):
                norm_flows.append(f)
            elif isinstance(f, dict):
                norm_flows.append(normalize_conn_record(f))

        norm_flows.sort(key=lambda x: x.timestamp)

        # 3. Stream through inference
        alerts: List[AlertEvent] = []
        for flow in norm_flows:
            alert = self.process_flow(flow)
            alerts.append(alert)

        return alerts

    def replay_directory(
        self,
        log_dir: Union[str, Path],
    ) -> Tuple[List[AlertEvent], Dict[str, Any]]:
        """
        Executes deterministic replay of Zeek log files from a directory on disk.
        Measures throughput, latency distributions, and detection summaries.
        """
        path = Path(log_dir).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Replay directory not found: {path}")

        t_wall_start = time.perf_counter()
        log_data = load_zeek_logs(path)
        alerts = self.process_log_batch(log_data)
        elapsed_wall = time.perf_counter() - t_wall_start

        perf_summary = self.get_performance_summary(elapsed_wall)
        return alerts, perf_summary

    def get_performance_summary(self, elapsed_wall_sec: Optional[float] = None) -> Dict[str, Any]:
        """Computes comprehensive throughput and latency statistics."""
        lats = np.array(self.latency_records_ms) if self.latency_records_ms else np.array([0.0])
        count = self.total_flows_processed

        wall_time = elapsed_wall_sec if elapsed_wall_sec is not None else (np.sum(lats) / 1000.0)
        throughput = round(float(count) / wall_time, 2) if wall_time > 0 else 0.0

        return {
            "total_flows_processed": count,
            "threats_detected": self.threats_detected,
            "benign_flows": self.benign_count,
            "abstained_reviews": self.abstained_reviews,
            "inference_errors": self.inference_errors,
            "mean_latency_ms": round(float(np.mean(lats)), 3),
            "p50_latency_ms": round(float(np.percentile(lats, 50)), 3),
            "p95_latency_ms": round(float(np.percentile(lats, 95)), 3),
            "p99_latency_ms": round(float(np.percentile(lats, 99)), 3),
            "max_latency_ms": round(float(np.max(lats)), 3),
            "throughput_flows_per_sec": throughput,
            "wall_clock_time_sec": round(float(wall_time), 4),
        }

    def attach_to_live_pipeline(
        self,
        live_pipeline: LiveZeekPipeline,
        alert_callback: Optional[Callable[[AlertEvent], None]] = None,
    ) -> Callable[[], List[AlertEvent]]:
        """
        Hooks the ML inference pipeline to a LiveZeekPipeline instance.
        Returns a single-poll function that reads newly appended Zeek logs,
        runs inference, invokes the optional callback, and returns generated alerts.
        """
        def poll_and_detect() -> List[AlertEvent]:
            poll_res = live_pipeline.poll_once()
            log_data = poll_res.get("logs", {})
            alerts = self.process_log_batch(log_data)
            if alert_callback:
                for a in alerts:
                    try:
                        alert_callback(a)
                    except Exception as e:
                        logger.error(f"Error executing alert callback: {e}")
            return alerts

        return poll_and_detect
