import React, { useMemo } from 'react';
import { DashboardFacets, NormalizedAlert } from '../types/wazuh';
import { getSeverityBand } from '../utils/wazuhParser';
import { severityBarFill, severityDotClass, severityTextClass } from '../utils/formatters';

interface AnalyticsViewProps {
  alerts: NormalizedAlert[];
  facets: DashboardFacets;
  onFilterAndOpenEvents: (
    type: 'ruleId' | 'agent' | 'decoder' | 'group' | 'mitre' | 'level',
    value: string
  ) => void;
}

export function AnalyticsView({
  alerts,
  facets,
  onFilterAndOpenEvents,
}: AnalyticsViewProps) {
  const levelDistribution = useMemo(() => {
    const counts = Array.from({ length: 16 }, (_, level) => ({ level, count: 0 }));
    for (const a of alerts) {
      const clamped = Math.max(0, Math.min(15, Math.round(a.level)));
      counts[clamped].count++;
    }
    return counts.filter((item) => item.count > 0);
  }, [alerts]);

  const locationCounts = useMemo(() => {
    const map = new Map<string, number>();
    for (const a of alerts) {
      map.set(a.location, (map.get(a.location) ?? 0) + 1);
    }
    return Array.from(map.entries())
      .map(([location, count]) => ({ location, count }))
      .sort((a, b) => b.count - a.count);
  }, [alerts]);

  const maxRuleCount = facets.topRules[0]?.count ?? 1;
  const maxGroupCount = facets.groups[0]?.count ?? 1;
  const maxDecoderCount = facets.decoders[0]?.count ?? 1;
  const maxMitreCount = facets.mitreItems[0]?.count ?? 1;
  const maxLevelCount = Math.max(1, ...levelDistribution.map((l) => l.count));

  if (alerts.length === 0) {
    return (
      <div className="border border-slate-200 dark:border-slate-800 rounded-lg bg-white dark:bg-slate-900/60 py-16 text-center text-sm text-slate-500 dark:text-slate-400">
        No matching alerts to analyze. Adjust your active filters or upload a Wazuh alerts file.
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
      {/* Top Triggered Rules */}
      <section className="border border-slate-200 dark:border-slate-800 rounded-lg bg-white dark:bg-slate-900/60 p-4">
        <div className="flex items-baseline justify-between mb-3">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
            Top Triggered Rules
          </h2>
          <span className="text-xs text-slate-500 dark:text-slate-400 tabular-nums">
            {facets.topRules.length} unique rules
          </span>
        </div>
        <div className="space-y-1">
          {facets.topRules.slice(0, 12).map((rule) => {
            const band = getSeverityBand(rule.level);
            const pct = Math.max(2, (rule.count / maxRuleCount) * 100);
            return (
              <button
                key={`${rule.ruleId}-${rule.description}`}
                type="button"
                onClick={() => onFilterAndOpenEvents('ruleId', rule.ruleId)}
                className="w-full text-left px-2.5 py-2 rounded-md hover:bg-slate-50 dark:hover:bg-slate-800/60 transition-colors group"
              >
                <div className="flex items-baseline justify-between gap-3 text-xs">
                  <div className="flex items-baseline gap-2 min-w-0">
                    <span className="font-mono font-semibold text-slate-800 dark:text-slate-200 tabular-nums flex-shrink-0">
                      {rule.ruleId}
                    </span>
                    <span className={`font-mono text-[11px] flex-shrink-0 ${severityTextClass(band)}`}>
                      L{rule.level}
                    </span>
                    <span className="text-slate-600 dark:text-slate-400 truncate group-hover:text-slate-900 dark:group-hover:text-slate-100">
                      {rule.description}
                    </span>
                  </div>
                  <span className="font-mono text-slate-700 dark:text-slate-300 tabular-nums flex-shrink-0">
                    {rule.count.toLocaleString()}
                  </span>
                </div>
                <div className="mt-1.5 h-1.5 w-full rounded-xs bg-slate-100 dark:bg-slate-800 overflow-hidden">
                  <div
                    className="h-full rounded-xs"
                    style={{ width: `${pct}%`, backgroundColor: severityBarFill(band) }}
                  />
                </div>
              </button>
            );
          })}
        </div>
      </section>

      {/* Rule Level Distribution (0-15) */}
      <section className="border border-slate-200 dark:border-slate-800 rounded-lg bg-white dark:bg-slate-900/60 p-4 flex flex-col justify-between">
        <div>
          <div className="flex items-baseline justify-between mb-3">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              Rule Level Distribution
            </h2>
            <span className="text-xs text-slate-500 dark:text-slate-400">
              Click a level to filter
            </span>
          </div>
          <div className="space-y-2">
            {levelDistribution.map(({ level, count }) => {
              const band = getSeverityBand(level);
              const pct = Math.max(2, (count / maxLevelCount) * 100);
              const share = ((count / alerts.length) * 100).toFixed(1);
              return (
                <button
                  key={level}
                  type="button"
                  onClick={() => onFilterAndOpenEvents('level', String(level))}
                  className="w-full text-left px-2.5 py-1.5 rounded-md hover:bg-slate-50 dark:hover:bg-slate-800/60 transition-colors"
                >
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="inline-flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-xs ${severityDotClass(band)}`} />
                      <span className="font-mono font-semibold text-slate-800 dark:text-slate-200 tabular-nums">
                        Level {level}
                      </span>
                      <span className={`text-[11px] capitalize ${severityTextClass(band)}`}>
                        {band}
                      </span>
                    </span>
                    <span className="font-mono text-slate-600 dark:text-slate-400 tabular-nums">
                      {count.toLocaleString()} ({share}%)
                    </span>
                  </div>
                  <div className="h-2 w-full rounded-xs bg-slate-100 dark:bg-slate-800 overflow-hidden">
                    <div
                      className="h-full rounded-xs"
                      style={{ width: `${pct}%`, backgroundColor: severityBarFill(band) }}
                    />
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Log Locations sub-summary */}
        <div className="mt-5 pt-4 border-t border-slate-200 dark:border-slate-800">
          <h3 className="text-xs font-semibold text-slate-800 dark:text-slate-200 mb-2">
            Log Sources & Locations
          </h3>
          <div className="divide-y divide-slate-100 dark:divide-slate-800/80 text-xs">
            {locationCounts.slice(0, 6).map(({ location, count }) => (
              <div key={location} className="py-1.5 flex items-center justify-between gap-3">
                <span className="font-mono text-[11px] text-slate-700 dark:text-slate-300 truncate">
                  {location}
                </span>
                <span className="font-mono text-slate-500 dark:text-slate-400 tabular-nums">
                  {count.toLocaleString()}
                </span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Rule Groups */}
      <section className="border border-slate-200 dark:border-slate-800 rounded-lg bg-white dark:bg-slate-900/60 p-4">
        <div className="flex items-baseline justify-between mb-3">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
            Rule Groups
          </h2>
          <span className="text-xs text-slate-500 dark:text-slate-400 tabular-nums">
            {facets.groups.length} groups
          </span>
        </div>
        <div className="space-y-1.5">
          {facets.groups.slice(0, 12).map((group) => {
            const pct = Math.max(2, (group.count / maxGroupCount) * 100);
            return (
              <button
                key={group.value}
                type="button"
                onClick={() => onFilterAndOpenEvents('group', group.value)}
                className="w-full text-left px-2 py-1.5 rounded-md hover:bg-slate-50 dark:hover:bg-slate-800/60 transition-colors"
              >
                <div className="flex items-center justify-between text-xs mb-1">
                  <span className="font-mono text-slate-700 dark:text-slate-300 truncate">
                    {group.label}
                  </span>
                  <span className="font-mono text-slate-500 dark:text-slate-400 tabular-nums">
                    {group.count.toLocaleString()}
                  </span>
                </div>
                <div className="h-1.5 w-full rounded-xs bg-slate-100 dark:bg-slate-800 overflow-hidden">
                  <div
                    className="h-full rounded-xs bg-blue-600 dark:bg-blue-500"
                    style={{ width: `${pct}%` }}
                  />
                </div>
              </button>
            );
          })}
        </div>
      </section>

      {/* Decoders & Agents / MITRE */}
      <section className="border border-slate-200 dark:border-slate-800 rounded-lg bg-white dark:bg-slate-900/60 p-4 space-y-5">
        <div>
          <div className="flex items-baseline justify-between mb-3">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              Decoders
            </h2>
            <span className="text-xs text-slate-500 dark:text-slate-400 tabular-nums">
              {facets.decoders.length} active
            </span>
          </div>
          <div className="space-y-1.5">
            {facets.decoders.slice(0, 8).map((dec) => {
              const pct = Math.max(2, (dec.count / maxDecoderCount) * 100);
              return (
                <button
                  key={dec.value}
                  type="button"
                  onClick={() => onFilterAndOpenEvents('decoder', dec.value)}
                  className="w-full text-left px-2 py-1.5 rounded-md hover:bg-slate-50 dark:hover:bg-slate-800/60 transition-colors"
                >
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="font-mono text-slate-700 dark:text-slate-300">
                      {dec.label}
                    </span>
                    <span className="font-mono text-slate-500 dark:text-slate-400 tabular-nums">
                      {dec.count.toLocaleString()}
                    </span>
                  </div>
                  <div className="h-1.5 w-full rounded-xs bg-slate-100 dark:bg-slate-800 overflow-hidden">
                    <div
                      className="h-full rounded-xs bg-slate-600 dark:bg-slate-400"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {facets.mitreItems.length > 0 && (
          <div className="pt-4 border-t border-slate-200 dark:border-slate-800">
            <div className="flex items-baseline justify-between mb-3">
              <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                MITRE ATT&CK Techniques
              </h2>
              <span className="text-xs text-slate-500 dark:text-slate-400 tabular-nums">
                {facets.mitreItems.length} mapped
              </span>
            </div>
            <div className="space-y-1.5">
              {facets.mitreItems.slice(0, 8).map((m) => {
                const pct = Math.max(2, (m.count / maxMitreCount) * 100);
                return (
                  <button
                    key={m.value}
                    type="button"
                    onClick={() => onFilterAndOpenEvents('mitre', m.value)}
                    className="w-full text-left px-2 py-1.5 rounded-md hover:bg-slate-50 dark:hover:bg-slate-800/60 transition-colors"
                  >
                    <div className="flex items-center justify-between text-xs mb-1">
                      <span className="font-mono text-slate-700 dark:text-slate-300">
                        {m.label}
                      </span>
                      <span className="font-mono text-slate-500 dark:text-slate-400 tabular-nums">
                        {m.count.toLocaleString()}
                      </span>
                    </div>
                    <div className="h-1.5 w-full rounded-xs bg-slate-100 dark:bg-slate-800 overflow-hidden">
                      <div
                        className="h-full rounded-xs bg-amber-600 dark:bg-amber-500"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        )}

        <div className="pt-4 border-t border-slate-200 dark:border-slate-800">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-2">
            Agents
          </h2>
          <div className="divide-y divide-slate-100 dark:divide-slate-800/80 text-xs">
            {facets.agents.map((ag) => (
              <button
                key={ag.value}
                type="button"
                onClick={() => onFilterAndOpenEvents('agent', ag.value)}
                className="w-full py-2 flex items-center justify-between gap-3 text-left hover:text-blue-600 dark:hover:text-blue-400 transition-colors"
              >
                <span className="flex items-baseline gap-2 min-w-0">
                  <span className="font-medium text-slate-800 dark:text-slate-200">
                    {ag.label}
                  </span>
                  {ag.sublabel && ag.sublabel !== '—' && (
                    <span className="font-mono text-[11px] text-slate-400 dark:text-slate-500">
                      {ag.sublabel}
                    </span>
                  )}
                </span>
                <span className="font-mono text-slate-600 dark:text-slate-400 tabular-nums">
                  {ag.count.toLocaleString()} alerts
                </span>
              </button>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}
