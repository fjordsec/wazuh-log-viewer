import {
  DashboardFacets,
  FacetItem,
  FilterState,
  NormalizedAlert,
  SeverityBand,
  SortDirection,
  SortField,
} from '../types/wazuh';

interface SearchToken {
  negated: boolean;
  field?: string;
  operator?: ':' | '>=' | '<=' | '>' | '<' | '=';
  value: string;
}

/**
 * Parses search query supporting:
 * - Free-text terms and "quoted phrases"
 * - Negation with -term or -field:value
 * - Field queries: rule:5402, rule.id:19007, level>=7, level:3, agent:dev01,
 *   ip:10.20.10.30, decoder:sudo, group:dpkg, mitre:T1548, sca:failed,
 *   user:root, pkg:ncat, cis:5.2, compliance:hipaa
 */
function parseSearchTokens(query: string): SearchToken[] {
  const tokens: SearchToken[] = [];
  const regex = /(-?)(?:([a-zA-Z0-9_.-]+)(>=|<=|>|<|:|=))?(?:"([^"]+)"|(\S+))/g;
  let match: RegExpExecArray | null;

  while ((match = regex.exec(query)) !== null) {
    const negated = match[1] === '-';
    const field = match[2]?.toLowerCase();
    const operator = match[3] as SearchToken['operator'] | undefined;
    const value = (match[4] ?? match[5] ?? '').toLowerCase().trim();
    if (!value) continue;
    tokens.push({ negated, field, operator, value });
  }

  return tokens;
}

function matchesSearchToken(alert: NormalizedAlert, token: SearchToken): boolean {
  const { field, operator, value } = token;

  if (!field) {
    return alert.searchCorpus.includes(value);
  }

  if (field === 'level' || field === 'rule.level') {
    const num = Number(value);
    if (Number.isNaN(num)) return false;
    if (operator === '>=') return alert.level >= num;
    if (operator === '<=') return alert.level <= num;
    if (operator === '>') return alert.level > num;
    if (operator === '<') return alert.level < num;
    return alert.level === num;
  }

  switch (field) {
    case 'rule':
    case 'rule.id':
    case 'ruleid':
      return alert.ruleId.toLowerCase().includes(value);
    case 'desc':
    case 'description':
    case 'rule.description':
      return alert.ruleDescription.toLowerCase().includes(value);
    case 'agent':
    case 'agent.name':
      return alert.agentName.toLowerCase().includes(value);
    case 'ip':
    case 'agent.ip':
      return alert.agentIp.toLowerCase().includes(value);
    case 'decoder':
    case 'decoder.name':
      return (
        alert.decoderName.toLowerCase().includes(value) ||
        (alert.decoderParent?.toLowerCase().includes(value) ?? false)
      );
    case 'group':
    case 'groups':
    case 'rule.groups':
      return alert.ruleGroups.some((g) => g.toLowerCase().includes(value));
    case 'mitre':
      return (
        alert.mitreIds.some((m) => m.toLowerCase().includes(value)) ||
        alert.mitreTactics.some((m) => m.toLowerCase().includes(value)) ||
        alert.mitreTechniques.some((m) => m.toLowerCase().includes(value))
      );
    case 'sca':
    case 'result':
      return (alert.scaResult ?? '').toLowerCase().includes(value);
    case 'cis':
      return (alert.cisId ?? '').toLowerCase().includes(value);
    case 'compliance':
      return alert.complianceFrameworks.some((c) => c.toLowerCase().includes(value));
    case 'location':
      return alert.location.toLowerCase().includes(value);
    case 'user':
    case 'srcuser':
    case 'dstuser':
      return (
        (alert.srcUser?.toLowerCase().includes(value) ?? false) ||
        (alert.dstUser?.toLowerCase().includes(value) ?? false)
      );
    case 'pkg':
    case 'package':
      return (alert.dpkgPackage?.toLowerCase().includes(value) ?? false);
    case 'severity':
      return alert.severity === value;
    default:
      return alert.searchCorpus.includes(`${field}:${value}`) || alert.searchCorpus.includes(value);
  }
}

export function filterAlerts(alerts: NormalizedAlert[], filters: FilterState): NormalizedAlert[] {
  const tokens = filters.search.trim() ? parseSearchTokens(filters.search) : [];

  return alerts.filter((alert) => {
    // Level range
    if (alert.level < filters.minLevel || alert.level > filters.maxLevel) {
      return false;
    }

    // Severity bands
    if (filters.severities.length > 0 && !filters.severities.includes(alert.severity)) {
      return false;
    }

    // Time range
    if (filters.timeRange) {
      const [start, end] = filters.timeRange;
      if (alert.timestampMs < start || alert.timestampMs > end) {
        return false;
      }
    }

    // Agents
    if (filters.agents.length > 0 && !filters.agents.includes(alert.agentName)) {
      return false;
    }

    // Decoders
    if (filters.decoders.length > 0 && !filters.decoders.includes(alert.decoderName)) {
      return false;
    }

    // Rule groups (match any selected group)
    if (
      filters.groups.length > 0 &&
      !filters.groups.some((g) => alert.ruleGroups.includes(g))
    ) {
      return false;
    }

    // Rule IDs
    if (filters.ruleIds.length > 0 && !filters.ruleIds.includes(alert.ruleId)) {
      return false;
    }

    // SCA results
    if (
      filters.scaResults.length > 0 &&
      (!alert.scaResult || !filters.scaResults.includes(alert.scaResult))
    ) {
      return false;
    }

    // MITRE
    if (filters.mitreItems.length > 0) {
      const alertMitre = new Set([...alert.mitreIds, ...alert.mitreTactics]);
      if (!filters.mitreItems.some((m) => alertMitre.has(m))) {
        return false;
      }
    }

    // Compliance frameworks
    if (
      filters.complianceFrameworks.length > 0 &&
      !filters.complianceFrameworks.some((cf) => alert.complianceFrameworks.includes(cf))
    ) {
      return false;
    }

    // Structured / full-text search tokens (AND across all tokens)
    for (const token of tokens) {
      const matched = matchesSearchToken(alert, token);
      if (token.negated ? matched : !matched) {
        return false;
      }
    }

    return true;
  });
}

export function sortAlerts(
  alerts: NormalizedAlert[],
  field: SortField,
  direction: SortDirection
): NormalizedAlert[] {
  const dir = direction === 'asc' ? 1 : -1;
  return [...alerts].sort((a, b) => {
    switch (field) {
      case 'timestampMs':
        return (a.timestampMs - b.timestampMs) * dir;
      case 'level':
        return (a.level - b.level) * dir || (b.timestampMs - a.timestampMs);
      case 'ruleId':
        return a.ruleId.localeCompare(b.ruleId, undefined, { numeric: true }) * dir;
      case 'agentName':
        return a.agentName.localeCompare(b.agentName) * dir;
      case 'decoderName':
        return a.decoderName.localeCompare(b.decoderName) * dir;
    }
  });
}

export function computeFacets(alerts: NormalizedAlert[]): DashboardFacets {
  const severities: Record<SeverityBand, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };

  const agentMap = new Map<string, { count: number; ip: string }>();
  const decoderMap = new Map<string, number>();
  const groupMap = new Map<string, number>();
  const scaResultMap = new Map<string, number>();
  const mitreMap = new Map<string, number>();
  const complianceMap = new Map<string, number>();
  const ruleMap = new Map<string, { ruleId: string; description: string; level: number; count: number }>();

  for (const a of alerts) {
    severities[a.severity]++;

    const ag = agentMap.get(a.agentName);
    if (ag) {
      ag.count++;
    } else {
      agentMap.set(a.agentName, { count: 1, ip: a.agentIp });
    }

    decoderMap.set(a.decoderName, (decoderMap.get(a.decoderName) ?? 0) + 1);

    for (const g of a.ruleGroups) {
      groupMap.set(g, (groupMap.get(g) ?? 0) + 1);
    }

    if (a.scaResult) {
      scaResultMap.set(a.scaResult, (scaResultMap.get(a.scaResult) ?? 0) + 1);
    }

    for (const m of a.mitreIds) {
      mitreMap.set(m, (mitreMap.get(m) ?? 0) + 1);
    }

    for (const cf of a.complianceFrameworks) {
      complianceMap.set(cf, (complianceMap.get(cf) ?? 0) + 1);
    }

    const ruleKey = `${a.ruleId}::${a.ruleDescription}`;
    const existingRule = ruleMap.get(ruleKey);
    if (existingRule) {
      existingRule.count++;
    } else {
      ruleMap.set(ruleKey, {
        ruleId: a.ruleId,
        description: a.ruleDescription,
        level: a.level,
        count: 1,
      });
    }
  }

  const toSortedFacets = (map: Map<string, number>): FacetItem[] =>
    Array.from(map.entries())
      .map(([value, count]) => ({ value, label: value, count }))
      .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));

  const agents: FacetItem[] = Array.from(agentMap.entries())
    .map(([name, info]) => ({
      value: name,
      label: name,
      sublabel: info.ip,
      count: info.count,
    }))
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));

  const topRules = Array.from(ruleMap.values()).sort(
    (a, b) => b.count - a.count || b.level - a.level
  );

  return {
    severities,
    agents,
    decoders: toSortedFacets(decoderMap),
    groups: toSortedFacets(groupMap),
    scaResults: toSortedFacets(scaResultMap),
    mitreItems: toSortedFacets(mitreMap),
    complianceFrameworks: toSortedFacets(complianceMap),
    topRules,
  };
}

export function hasActiveFilters(filters: FilterState): boolean {
  return (
    filters.search.trim().length > 0 ||
    filters.severities.length > 0 ||
    filters.minLevel > 0 ||
    filters.maxLevel < 15 ||
    filters.agents.length > 0 ||
    filters.decoders.length > 0 ||
    filters.groups.length > 0 ||
    filters.ruleIds.length > 0 ||
    filters.scaResults.length > 0 ||
    filters.mitreItems.length > 0 ||
    filters.complianceFrameworks.length > 0 ||
    filters.timeRange !== null
  );
}

export function exportAlertsToCsv(alerts: NormalizedAlert[], filename: string): void {
  const headers = [
    'timestamp',
    'level',
    'severity',
    'rule_id',
    'rule_description',
    'agent_name',
    'agent_ip',
    'decoder',
    'location',
    'groups',
    'mitre_ids',
    'sca_result',
    'full_log',
  ];

  const escapeCsv = (val: string | number | undefined): string => {
    const str = val === undefined || val === null ? '' : String(val);
    if (/[",\n\r]/.test(str)) {
      return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
  };

  const rows = alerts.map((a) =>
    [
      a.timestampIso,
      a.level,
      a.severity,
      a.ruleId,
      a.ruleDescription,
      a.agentName,
      a.agentIp,
      a.decoderName,
      a.location,
      a.ruleGroups.join('|'),
      a.mitreIds.join('|'),
      a.scaResult ?? '',
      a.fullLog ?? '',
    ]
      .map(escapeCsv)
      .join(',')
  );

  const blob = new Blob([[headers.join(','), ...rows].join('\n')], {
    type: 'text/csv;charset=utf-8;',
  });
  triggerDownload(blob, filename);
}

export function exportAlertsToJson(alerts: NormalizedAlert[], filename: string): void {
  const payload = alerts.map((a) => a.raw);
  const blob = new Blob([JSON.stringify(payload, null, 2)], {
    type: 'application/json;charset=utf-8;',
  });
  triggerDownload(blob, filename);
}

function triggerDownload(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}
