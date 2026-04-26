export interface IDSFlow {
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  prediction: number | string;
}

export interface FlowDisplay {
  id: string; // Unique ID for React rendering
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  // NOTE: Prediction is intentionally omitted per requirements.
  // Actually, we need it in the frontend maybe for charting, explicitly requirement says:
  // "Prediction must NOT be shown in the table."
  // We will keep prediction in the interface but not render it in the table.
  prediction: number | string;
  isSuspicious: boolean;
}

export interface AttackEvent {
  attack_id: string;
  attack_start_time: string;
  attack_end_time: string;
  duration_seconds: number;
  source_ip: string;
  destination_ip: string;
  source_port: number;
  destination_port: number;
  attack_type: number | string;
  flow_count: number;
}

export type ThreatLevel = 'SAFE' | 'WARNING' | 'DANGER';

export interface DashboardStats {
  totalFlowsProcessed: number;
  totalAttacksDetected: number;
  currentThreatLevel: ThreatLevel;
}

export interface AttackAlertEvent {
  message: string;
  attackClass?: number | string;
  flows: FlowDisplay[];
}
