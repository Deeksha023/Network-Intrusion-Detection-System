/**
 * Shared TypeScript type definitions for Enterprise SOC IDS Platform.
 */

export type SeverityLevel = 'low' | 'medium' | 'high' | 'critical'

export interface ShapExplanation {
  feature_names: string[]
  shap_values: number[]
  base_value: number
  explanation_type?: string
  is_global_fallback?: boolean
  note?: string
}

export interface Alert {
  id: string
  timestamp: string
  flow_id: string
  stage: 1 | 2
  attack_type: string | null
  confidence: number
  severity: SeverityLevel
  reconstruction_error: number | null
  shap_explanation: ShapExplanation | null
  src_ip?: string
  dst_ip?: string
  src_port?: number
  dst_port?: number
  protocol?: string
  raw_features?: Record<string, number> | null
  assigned_to?: string
  notes?: string
  tags?: string[]
  reviewed?: boolean
  feedback_label?: string
  threat_intel?: ThreatIntelData
}

export interface AlertListResponse {
  total: number
  page: number
  page_size: number
  total_pages: number
  items: Alert[]
}

export interface SystemHealth {
  status: 'ok' | 'degraded' | 'error'
  version: string
  postgres: boolean
  redis: boolean
  ml_models_loaded: {
    classifier: boolean
    autoencoder: boolean
  }
  worker_status: 'running' | 'stopped'
  active_ws_connections: number
  uptime_seconds: number
}

export interface MetricsOverview {
  today_alerts: number
  critical_alerts: number
  high_alerts: number
  medium_alerts: number
  low_alerts: number
  top_attacks: Array<{ attack_type: string; count: number }>
  benign_vs_malicious: {
    benign: number
    malicious: number
  }
  protocols: Array<{ protocol: string; count: number }>
  total_alerts: number
}

export interface TimelineItem {
  timestamp: string
  total: number
  low: number
  medium: number
  high: number
  critical: number
}

export interface TimelineResponse {
  interval: string
  start_ts: string
  end_ts: string
  total_buckets: number
  timeline: TimelineItem[]
}

export interface TrafficStats {
  type: 'traffic_stats'
  timestamp: string
  total_flows_processed: number
  total_alerts_generated: number
  status: string
  packets_per_sec?: number
  bytes_per_sec?: number
  active_flows?: number
  top_src_ips?: Array<{ ip: string; count: number }>
}

export interface NetworkInterface {
  name: string
  description: string
  mac_address: string
  ip_address: string
  status: 'up' | 'down' | string
  speed: string
}

export interface LiveAlertSummary {
  id: string
  timestamp: string
  stage: 1 | 2
  attack_type: string
  severity: SeverityLevel
  confidence: number
}

export interface MonitorStatus {
  active: boolean
  interface: string | null
  uptime_seconds: number
  packets_per_sec: number
  flows_per_sec: number
  active_flows: number
  bandwidth_bps: number
  total_packets_captured: number
  total_flows_processed: number
  known_attacks_detected: number
  unknown_attacks_detected: number
  error_message: string | null
  latest_live_alerts?: LiveAlertSummary[]
}

export interface User {
  id: string
  username: string
  email: string
  role: 'admin' | 'analyst' | 'viewer'
  is_active: boolean
}

export interface ThreatIntelData {
  ip: string
  is_private: boolean
  country: string
  city: string
  latitude: number
  longitude: number
  asn: string
  isp: string
  abuse_score: number
  reputation_score: number
  last_reported: string | null
  threat_category: string
  known_malicious: boolean
  organization: string
}

export interface AuditLog {
  id: string
  timestamp: string
  username: string
  action: string
  target: string
  details: Record<string, unknown>
}

export interface ModelEvaluationMetrics {
  evaluation_scope?: string
  dataset?: string
  train_test_split?: string
  total_test_samples?: number
  benign_samples?: number
  attack_samples?: number
  num_attack_classes?: number
  num_features?: number
  confusion_matrix: {
    tp: number
    tn: number
    fp: number
    fn: number
    total_evaluated: number
  }

  metrics: {
    accuracy: number
    precision: number
    recall: number
    specificity: number
    f1_score: number
    false_positive_rate: number
    false_negative_rate: number
    balanced_accuracy: number
    mcc: number
    roc_auc: number
  }
  roc_curve: Array<{ fpr: number; tpr: number }>
  precision_recall_curve: Array<{ recall: number; precision: number }>
  feedback_counts: {
    total_analyst_reviews: number
    confirmed_attacks: number
    false_positives: number
    benign_confirmed: number
  }
}

export interface IncidentRules {
  firewall_rules: string[]
  whitelist: string[]
  blacklist: string[]
}

export interface SimulationResult {
  status: string
  attack_type: string
  packets_generated: number
  flows_generated: number
  target_ip: string
  detection_time_ms: number
  known_attack_result: string
  unknown_attack_result: string
}

export interface ModelComparisonData {
  stage1_randomforest?: {
    accuracy: number
    precision: number
    recall: number
    f1_score: number
    processing_time_ms: number
    detection_scope: string
  }
  stage2_autoencoder?: {
    accuracy: number
    precision: number
    recall: number
    f1_score: number
    detection_latency_ms: number
    detection_scope: string
  }
}

export interface ReportGenerationResponse {
  report_id: string
  status: string
  created_at: string
  report?: {
    title?: string
    metrics?: {
      total_alerts: number
      known_attacks: number
      zero_day_anomalies: number
      critical_severity: number
    }
    recommendations?: string[]
  }
}

export interface AnalyticsOverview {
  top_attacks: Array<{ attack_type: string; count: number }>
  top_sources: Array<{ ip: string; country: string; count: number }>
  top_ports: Array<{ port: number; count: number }>
}

export type WebSocketMessage =
  | { type: 'connected'; channel: string; recent_alerts?: Alert[] }
  | { type: 'ping' }
  | Alert
  | TrafficStats
