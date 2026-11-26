import { NormalizedAlert, ParseResult, ScaData, SeverityBand } from '../types/wazuh';

export function getSeverityBand(level: number): SeverityBand {
  if (level >= 12) return 'critical';
  if (level >= 8) return 'high';
  if (level >= 4) return 'medium';
  return 'low';
}

export function getSeverityLabel(band: SeverityBand): string {
  switch (band) {
    case 'critical':
      return 'Critical';
    case 'high':
      return 'High';
    case 'medium':
      return 'Medium';
    case 'low':
      return 'Low';
  }
}

const COMPLIANCE_LABEL_MAP: Record<string, string> = {
  pci_dss: 'PCI-DSS',
  hipaa: 'HIPAA',
  gdpr: 'GDPR',
  nist_800_53: 'NIST 800-53',
  'nist_sp_800-53': 'NIST SP 800-53',
  tsc: 'TSC',
  gpg13: 'GPG13',
  cis: 'CIS',
  cis_csc_v7: 'CIS CSC v7',
  cis_csc_v8: 'CIS CSC v8',
  soc_2: 'SOC 2',
  'iso_27001-2013': 'ISO 27001',
};

function asStringArray(value: unknown): string[] {
  if (!value) return [];
  if (Array.isArray(value)) {
    return value.map((v) => String(v)).filter(Boolean);
  }
  if (typeof value === 'string') {
    return value
      .split(',')
      .map((v) => v.trim())
      .filter(Boolean);
  }
  return [];
}

function parseTimestamp(source: Record<string, unknown>, sortVal?: unknown): { iso: string; ms: number } {
  const candidates = [source['@timestamp'], source['timestamp']];
  for (const candidate of candidates) {
    if (typeof candidate === 'string' && candidate.trim()) {
      // Handle +0000 offset format safely in all browsers
      const normalized = candidate.replace(/([+-]\d{2})(\d{2})$/, '$1:$2');
      const ms = Date.parse(normalized);
      if (!Number.isNaN(ms)) {
        return { iso: new Date(ms).toISOString(), ms };
      }
    }
  }
  if (Array.isArray(sortVal) && typeof sortVal[0] === 'number' && !Number.isNaN(sortVal[0])) {
    return { iso: new Date(sortVal[0]).toISOString(), ms: sortVal[0] };
  }
  return { iso: '', ms: 0 };
}

function normalizeSingleAlert(item: Record<string, unknown>, fallbackIndex: number): NormalizedAlert {
  const isEsHit = typeof item._source === 'object' && item._source !== null;
  const source = (isEsHit ? item._source : item) as Record<string, unknown>;
  const index = typeof item._index === 'string' ? item._index : 'wazuh-alerts';
  const esId = typeof item._id === 'string' ? item._id : undefined;

  const rule = (source.rule && typeof source.rule === 'object' ? source.rule : {}) as Record<string, unknown>;
  const agent = (source.agent && typeof source.agent === 'object' ? source.agent : {}) as Record<string, unknown>;
  const manager = (source.manager && typeof source.manager === 'object' ? source.manager : {}) as Record<string, unknown>;
  const decoder = (source.decoder && typeof source.decoder === 'object' ? source.decoder : {}) as Record<string, unknown>;
  const predecoder = (source.predecoder && typeof source.predecoder === 'object' ? source.predecoder : {}) as Record<string, unknown>;
  const data = (source.data && typeof source.data === 'object' ? source.data : {}) as Record<string, unknown>;

  const { iso: timestampIso, ms: timestampMs } = parseTimestamp(source, item.sort);

  const rawLevel = Number(rule.level ?? 0);
  const level = Number.isFinite(rawLevel) ? rawLevel : 0;
  const severity = getSeverityBand(level);

  const ruleId = String(rule.id ?? 'unknown');
  const ruleDescription = String(rule.description ?? 'No rule description');
  const ruleGroups = asStringArray(rule.groups);
  const firedTimes = Number(rule.firedtimes ?? 1) || 1;

  const agentId = String(agent.id ?? '000');
  const agentName = String(agent.name ?? 'unknown');
  const agentIp = String(agent.ip ?? '—');
  const managerName = String(manager.name ?? '—');

  const decoderName = String(decoder.name ?? 'unknown');
  const decoderParent = typeof decoder.parent === 'string' ? decoder.parent : undefined;
  const location = String(source.location ?? '—');
  const programName = typeof predecoder.program_name === 'string' ? predecoder.program_name : undefined;
  const hostname = typeof predecoder.hostname === 'string' ? predecoder.hostname : undefined;
  const fullLog = typeof source.full_log === 'string' ? source.full_log : undefined;

  const srcUser = typeof data.srcuser === 'string' ? data.srcuser : undefined;
  const dstUser = typeof data.dstuser === 'string' ? data.dstuser : undefined;
  const command = typeof data.command === 'string' ? data.command : undefined;
  const pwd = typeof data.pwd === 'string' ? data.pwd : undefined;

  const dpkgPackage = typeof data.package === 'string' ? data.package : undefined;
  const dpkgStatus = typeof data.dpkg_status === 'string' ? data.dpkg_status : undefined;
  const dpkgVersion = typeof data.version === 'string' ? data.version : undefined;

  const sca = data.sca && typeof data.sca === 'object' ? (data.sca as ScaData) : undefined;
  const scaResult = sca
    ? sca.type === 'summary'
      ? 'summary'
      : sca.check?.result
        ? String(sca.check.result).toLowerCase()
        : undefined
    : undefined;

  // Normalize MITRE ATT&CK across both standard rule.mitre and SCA rule.mitre_* fields
  const mitreObj = (rule.mitre && typeof rule.mitre === 'object' ? rule.mitre : {}) as Record<string, unknown>;
  const mitreIdsSet = new Set<string>([
    ...asStringArray(mitreObj.id),
    ...asStringArray(rule.mitre_techniques),
  ]);
  const mitreTacticsSet = new Set<string>([
    ...asStringArray(mitreObj.tactic),
    ...asStringArray(rule.mitre_tactics),
  ]);
  const mitreTechniquesSet = new Set<string>([
    ...asStringArray(mitreObj.technique),
  ]);

  const mitreIds = Array.from(mitreIdsSet);
  const mitreTactics = Array.from(mitreTacticsSet);
  const mitreTechniques = Array.from(mitreTechniquesSet);

  // Compliance extraction
  const compliance: Record<string, string[]> = {};
  const complianceFrameworks: string[] = [];
  for (const [key, label] of Object.entries(COMPLIANCE_LABEL_MAP)) {
    const vals = asStringArray(rule[key]);
    if (vals.length > 0) {
      compliance[label] = vals;
      complianceFrameworks.push(label);
    }
  }

  const cisArr = asStringArray(rule.cis);
  const cisId = cisArr[0];

  const alertId = String(source.id ?? esId ?? `alert-${fallbackIndex}`);
  const uid = esId ? `${esId}-${fallbackIndex}` : `${alertId}-${fallbackIndex}`;

  const searchParts = [
    alertId,
    ruleId,
    ruleDescription,
    ruleGroups.join(' '),
    agentName,
    agentIp,
    agentId,
    managerName,
    decoderName,
    decoderParent ?? '',
    location,
    programName ?? '',
    hostname ?? '',
    fullLog ?? '',
    srcUser ?? '',
    dstUser ?? '',
    command ?? '',
    dpkgPackage ?? '',
    dpkgStatus ?? '',
    sca?.policy ?? '',
    sca?.check?.title ?? '',
    sca?.check?.description ?? '',
    sca?.check?.remediation ?? '',
    sca?.check?.result ?? '',
    cisId ?? '',
    mitreIds.join(' '),
    mitreTactics.join(' '),
    mitreTechniques.join(' '),
    complianceFrameworks.join(' '),
  ];

  return {
    uid,
    id: alertId,
    index,
    timestampIso,
    timestampMs,
    level,
    severity,
    ruleId,
    ruleDescription,
    ruleGroups,
    firedTimes,
    agentId,
    agentName,
    agentIp,
    managerName,
    decoderName,
    decoderParent,
    location,
    programName,
    hostname,
    fullLog,
    srcUser,
    dstUser,
    command,
    pwd,
    dpkgPackage,
    dpkgStatus,
    dpkgVersion,
    sca,
    scaResult,
    cisId,
    mitreIds,
    mitreTactics,
    mitreTechniques,
    compliance,
    complianceFrameworks,
    searchCorpus: searchParts.join(' ').toLowerCase(),
    raw: item,
  };
}

export function parseWazuhFileContent(rawText: string): ParseResult {
  const trimmed = rawText.trim();
  if (!trimmed) {
    throw new Error('The file is empty.');
  }

  // First try parsing as a single JSON document
  try {
    const parsed = JSON.parse(trimmed) as unknown;

    // 1. OpenSearch / Elasticsearch search response: { hits: { hits: [...] } }
    if (
      parsed &&
      typeof parsed === 'object' &&
      !Array.isArray(parsed) &&
      'hits' in parsed
    ) {
      const hitsWrapper = (parsed as { hits?: { hits?: unknown[]; total?: { value?: number } | number } }).hits;
      if (hitsWrapper && Array.isArray(hitsWrapper.hits)) {
        const alerts = hitsWrapper.hits
          .filter((h): h is Record<string, unknown> => Boolean(h && typeof h === 'object'))
          .map((h, i) => normalizeSingleAlert(h, i));
        const totalVal =
          typeof hitsWrapper.total === 'number'
            ? hitsWrapper.total
            : typeof hitsWrapper.total?.value === 'number'
              ? hitsWrapper.total.value
              : undefined;
        return {
          alerts,
          formatDetected: 'OpenSearch / Elasticsearch Export',
          totalReportedInFile: totalVal,
          skippedLines: 0,
        };
      }
    }

    // 2. JSON Array of alerts or ES hits
    if (Array.isArray(parsed)) {
      const alerts = parsed
        .filter((h): h is Record<string, unknown> => Boolean(h && typeof h === 'object'))
        .map((h, i) => normalizeSingleAlert(h, i));
      return {
        alerts,
        formatDetected: 'JSON Array',
        skippedLines: 0,
      };
    }

    // 3. Wrapper object like { alerts: [...] } or { data: [...] }
    if (parsed && typeof parsed === 'object') {
      const obj = parsed as Record<string, unknown>;
      const list = Array.isArray(obj.alerts)
        ? obj.alerts
        : Array.isArray(obj.data)
          ? obj.data
          : Array.isArray(obj.items)
            ? obj.items
            : null;
      if (list) {
        const alerts = list
          .filter((h): h is Record<string, unknown> => Boolean(h && typeof h === 'object'))
          .map((h, i) => normalizeSingleAlert(h, i));
        return {
          alerts,
          formatDetected: 'Wrapped JSON List',
          skippedLines: 0,
        };
      }

      // 4. Single alert object
      if ('rule' in obj || '_source' in obj || 'agent' in obj) {
        return {
          alerts: [normalizeSingleAlert(obj, 0)],
          formatDetected: 'Single Wazuh Alert',
          skippedLines: 0,
        };
      }
    }
  } catch {
    // Fall through to NDJSON / JSON Lines parsing
  }

  // 5. NDJSON / JSON Lines (e.g. /var/ossec/logs/alerts/alerts.json)
  const lines = trimmed.split(/\r?\n/);
  const alerts: NormalizedAlert[] = [];
  let skippedLines = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    try {
      const obj = JSON.parse(line) as unknown;
      if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
        alerts.push(normalizeSingleAlert(obj as Record<string, unknown>, i));
      } else {
        skippedLines++;
      }
    } catch {
      skippedLines++;
    }
  }

  if (alerts.length === 0) {
    throw new Error(
      'Unable to parse Wazuh alerts. Expected OpenSearch export JSON, a JSON array, or newline-delimited JSON (alerts.json).'
    );
  }

  return {
    alerts,
    formatDetected: 'NDJSON / JSON Lines',
    skippedLines,
  };
}
