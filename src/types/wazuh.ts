export type SeverityBand = 'critical' | 'high' | 'medium' | 'low';

export interface ScaCheckData {
  id?: string;
  title?: string;
  description?: string;
  rationale?: string;
  remediation?: string;
  result?: string;
  reason?: string;
  references?: string;
  command?: string[];
  file?: string[];
  directory?: string[];
  compliance?: Record<string, unknown>;
}

export interface ScaData {
  scan_id?: string;
  policy?: string;
  policy_id?: string;
  type?: 'check' | 'summary' | string;
  score?: string | number;
  passed?: string | number;
  failed?: string | number;
  invalid?: string | number;
  total_checks?: string | number;
  description?: string;
  file?: string;
  check?: ScaCheckData;
}

export interface NormalizedAlert {
  uid: string;
  id: string;
  index: string;
  timestampIso: string;
  timestampMs: number;
  level: number;
  severity: SeverityBand;
  ruleId: string;
  ruleDescription: string;
  ruleGroups: string[];
  firedTimes: number;
  agentId: string;
  agentName: string;
  agentIp: string;
  managerName: string;
  decoderName: string;
  decoderParent?: string;
  location: string;
  programName?: string;
  hostname?: string;
  fullLog?: string;
  srcUser?: string;
  dstUser?: string;
  command?: string;
  pwd?: string;
  dpkgPackage?: string;
  dpkgStatus?: string;
  dpkgVersion?: string;
  sca?: ScaData;
  scaResult?: string;
  cisId?: string;
  mitreIds: string[];
  mitreTactics: string[];
  mitreTechniques: string[];
  compliance: Record<string, string[]>;
  complianceFrameworks: string[];
  searchCorpus: string;
  raw: Record<string, unknown>;
}

export interface ParseResult {
  alerts: NormalizedAlert[];
  formatDetected: string;
  totalReportedInFile?: number;
  skippedLines: number;
}

export interface FilterState {
  search: string;
  severities: SeverityBand[];
  minLevel: number;
  maxLevel: number;
  agents: string[];
  decoders: string[];
  groups: string[];
  ruleIds: string[];
  scaResults: string[];
  mitreItems: string[];
  complianceFrameworks: string[];
  timeRange: [number, number] | null;
}

export type SortField = 'timestampMs' | 'level' | 'ruleId' | 'agentName' | 'decoderName';
export type SortDirection = 'asc' | 'desc';

export interface FacetItem {
  value: string;
  label: string;
  sublabel?: string;
  count: number;
}

export interface DashboardFacets {
  severities: Record<SeverityBand, number>;
  agents: FacetItem[];
  decoders: FacetItem[];
  groups: FacetItem[];
  scaResults: FacetItem[];
  mitreItems: FacetItem[];
  complianceFrameworks: FacetItem[];
  topRules: Array<{ ruleId: string; description: string; level: number; count: number }>;
}

export const INITIAL_FILTER_STATE: FilterState = {
  search: '',
  severities: [],
  minLevel: 0,
  maxLevel: 15,
  agents: [],
  decoders: [],
  groups: [],
  ruleIds: [],
  scaResults: [],
  mitreItems: [],
  complianceFrameworks: [],
  timeRange: null,
};
