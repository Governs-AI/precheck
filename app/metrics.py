"""
Prometheus metrics for GovernsAI Precheck service
"""

from prometheus_client import Counter, Histogram, Gauge, Info, generate_latest, CONTENT_TYPE_LATEST
from typing import Dict, Any
import time

# Counter metrics
precheck_requests_total = Counter(
    'precheck_requests_total',
    'Total number of precheck requests',
    ['user_id', 'tool', 'decision', 'policy_id']
)

postcheck_requests_total = Counter(
    'postcheck_requests_total', 
    'Total number of postcheck requests',
    ['user_id', 'tool', 'decision', 'policy_id']
)

pii_detections_total = Counter(
    'pii_detections_total',
    'Total number of PII detections',
    ['pii_type', 'action']
)

policy_evaluations_total = Counter(
    'policy_evaluations_total',
    'Total number of policy evaluations',
    ['tool', 'direction', 'policy_id']
)

webhook_events_total = Counter(
    'webhook_events_total',
    'Total number of webhook events emitted',
    ['event_type', 'status']
)

dlq_events_total = Counter(
    'dlq_events_total',
    'Total number of events written to dead letter queue',
    ['error_type']
)

auth_failures_total = Counter(
    'auth_failures_total',
    'Total number of authentication failures',
    ['reason']
)

request_errors_total = Counter(
    'request_errors_total',
    'Total number of request processing errors',
    ['endpoint', 'error_type']
)

# Histogram metrics
precheck_duration_seconds = Histogram(
    'precheck_duration_seconds',
    'Duration of precheck requests in seconds',
    ['user_id', 'tool'],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
)

postcheck_duration_seconds = Histogram(
    'postcheck_duration_seconds', 
    'Duration of postcheck requests in seconds',
    ['user_id', 'tool'],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
)

policy_evaluation_duration_seconds = Histogram(
    'policy_evaluation_duration_seconds',
    'Duration of policy evaluation in seconds',
    ['tool', 'policy_id'],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
)

pii_detection_duration_seconds = Histogram(
    'pii_detection_duration_seconds',
    'Duration of PII detection in seconds',
    ['pii_type'],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
)

webhook_duration_seconds = Histogram(
    'webhook_duration_seconds',
    'Duration of webhook requests in seconds',
    ['status'],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
)

# Gauge metrics
active_requests = Gauge(
    'active_requests',
    'Number of active requests currently being processed',
    ['endpoint']
)

policy_cache_size = Gauge(
    'policy_cache_size',
    'Number of policies in cache'
)

dlq_size = Gauge(
    'dlq_size',
    'Number of events in dead letter queue'
)

# Info metrics
service_info = Info(
    'precheck_service_info',
    'Information about the precheck service'
)

def record_precheck_request(user_id: str, tool: str, decision: str, policy_id: str, duration: float):
    """Record a precheck request metric"""
    precheck_requests_total.labels(
        user_id=user_id,
        tool=tool,
        decision=decision,
        policy_id=policy_id
    ).inc()
    
    precheck_duration_seconds.labels(
        user_id=user_id,
        tool=tool
    ).observe(duration)

def record_postcheck_request(user_id: str, tool: str, decision: str, policy_id: str, duration: float):
    """Record a postcheck request metric"""
    postcheck_requests_total.labels(
        user_id=user_id,
        tool=tool,
        decision=decision,
        policy_id=policy_id
    ).inc()
    
    postcheck_duration_seconds.labels(
        user_id=user_id,
        tool=tool
    ).observe(duration)

def record_pii_detection(pii_type: str, action: str, duration: float):
    """Record a PII detection metric"""
    pii_detections_total.labels(
        pii_type=pii_type,
        action=action
    ).inc()
    
    pii_detection_duration_seconds.labels(
        pii_type=pii_type
    ).observe(duration)

def record_policy_evaluation(tool: str, direction: str, policy_id: str, duration: float):
    """Record a policy evaluation metric"""
    policy_evaluations_total.labels(
        tool=tool,
        direction=direction,
        policy_id=policy_id
    ).inc()
    
    policy_evaluation_duration_seconds.labels(
        tool=tool,
        policy_id=policy_id
    ).observe(duration)

def record_webhook_event(event_type: str, status: str, duration: float):
    """Record a webhook event metric"""
    webhook_events_total.labels(
        event_type=event_type,
        status=status
    ).inc()
    
    webhook_duration_seconds.labels(
        status=status
    ).observe(duration)

def record_dlq_event(error_type: str):
    """Record a DLQ event metric"""
    dlq_events_total.labels(
        error_type=error_type
    ).inc()

def record_auth_failure(reason: str):
    """Record an authentication failure."""
    auth_failures_total.labels(
        reason=reason
    ).inc()

def record_request_error(endpoint: str, error_type: str):
    """Record request processing errors by endpoint."""
    request_errors_total.labels(
        endpoint=endpoint,
        error_type=error_type
    ).inc()

def set_active_requests(endpoint: str, count: int):
    """Set the number of active requests"""
    active_requests.labels(endpoint=endpoint).set(count)

def set_policy_cache_size(size: int):
    """Set the policy cache size"""
    policy_cache_size.set(size)

def set_dlq_size(size: int):
    """Set the DLQ size"""
    dlq_size.set(size)

def set_service_info(version: str, build_date: str, git_commit: str):
    """Set service information"""
    service_info.info({
        'version': version,
        'build_date': build_date,
        'git_commit': git_commit
    })

def get_metrics() -> str:
    """Get Prometheus metrics in text format"""
    return generate_latest()

def get_metrics_content_type() -> str:
    """Get the content type for metrics response"""
    return CONTENT_TYPE_LATEST
