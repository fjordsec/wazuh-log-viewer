import React, { useMemo, useState } from 'react';
import { Check, ChevronDown, ChevronRight, Copy, ShieldCheck } from 'lucide-react';
import { NormalizedAlert } from '../types/wazuh';
import { formatScaResultLabel, scaResultTextClass } from '../utils/formatters';

interface ScaViewProps {
  alerts: NormalizedAlert[];
  onInspectAlert: (alert: NormalizedAlert) => void;
}

type StatusFilter = 'all' | 'failed' | 'passed' | 'not applicable';

export function ScaView({ alerts, onInspectAlert }: ScaViewProps) {
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [localQuery, setLocalQuery] = useState('');
  const [expandedUid, setExpandedUid] = useState<string | null>(null);
  const [copiedUid, setCopiedUid] = useState<string | null>(null);

  const { summaryAlert, checks, counts, policyName } = useMemo(() => {
    const scaAlerts = alerts.filter((a) => Boolean(a.sca));
    const summary = scaAlerts.find((a) => a.sca?.type === 'summary') ?? null;
    const checkList = scaAlerts.filter((a) => a.sca?.check);

    let failed = 0;
    let passed = 0;
    let notApplicable = 0;
    for (const c of checkList) {
      const r = (c.scaResult ?? '').toLowerCase();
      if (r === 'failed') failed++;
      else if (r === 'passed') passed++;
      else notApplicable++;
    }

    const policy =
      summary?.sca?.policy ?? checkList[0]?.sca?.policy ?? 'Security Configuration Assessment';

    return {
      summaryAlert: summary,
      checks: checkList,
      counts: {
        total: checkList.length,
        failed,
        passed,
        notApplicable,
      },
      policyName: policy,
    };
  }, [alerts]);

  const filteredChecks = useMemo(() => {
    const q = localQuery.trim().toLowerCase();
    return checks.filter((c) => {
      if (statusFilter !== 'all') {
        const res = (c.scaResult ?? '').toLowerCase();
        if (statusFilter === 'not applicable') {
          if (res === 'failed' || res === 'passed') return false;
        } else if (res !== statusFilter) {
          return false;
        }
      }
      if (!q) return true;
      return (
        (c.cisId?.toLowerCase().includes(q) ?? false) ||
        (c.sca?.check?.title?.toLowerCase().includes(q) ?? false) ||
        (c.sca?.check?.remediation?.toLowerCase().includes(q) ?? false) ||
        c.ruleDescription.toLowerCase().includes(q)
      );
    });
  }, [checks, statusFilter, localQuery]);

  if (checks.length === 0 && !summaryAlert) {
    return (
      <div className="border border-slate-200 dark:border-slate-800 rounded-lg bg-white dark:bg-slate-900/60 py-16 px-6 text-center">
        <ShieldCheck className="w-8 h-8 text-slate-400 dark:text-slate-500 mx-auto mb-3" />
        <p className="text-sm font-medium text-slate-800 dark:text-slate-200">
          No SCA benchmark checks in current filter view
        </p>
        <p className="mt-1 text-xs text-slate-500 dark:text-slate-400 max-w-md mx-auto">
          Upload a Wazuh alerts export containing Security Configuration Assessment (decoder: sca)
          events, or clear active filters to inspect CIS benchmark results.
        </p>
      </div>
    );
  }

  const reportedScore =
    summaryAlert?.sca?.score !== undefined
      ? Number(summaryAlert.sca.score)
      : counts.passed + counts.failed > 0
        ? Math.round((counts.passed / (counts.passed + counts.failed)) * 100)
        : 0;

  const copyRemediation = (uid: string, text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedUid(uid);
      window.setTimeout(() => setCopiedUid((prev) => (prev === uid ? null : prev)), 1600);
    });
  };

  return (
    <div className="space-y-4">
      {/* Posture summary strip */}
      <section className="border border-slate-200 dark:border-slate-800 rounded-lg bg-white dark:bg-slate-900/60 p-4">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              {policyName}
            </h2>
            <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
              {summaryAlert?.sca?.total_checks
                ? `Scan reported ${summaryAlert.sca.total_checks} total policy checks (${summaryAlert.sca.passed ?? 0} passed, ${summaryAlert.sca.failed ?? 0} failed, ${summaryAlert.sca.invalid ?? 0} invalid). Showing ${counts.total} check alerts in current dataset.`
                : `Showing ${counts.total} individual SCA check alerts in the current filter view.`}
            </p>
          </div>

          <div className="flex items-center gap-6 tabular-nums">
            <div>
              <div className="text-[11px] text-slate-500 dark:text-slate-400">Score</div>
              <div className="text-xl font-semibold font-mono text-slate-900 dark:text-slate-100">
                {reportedScore}%
              </div>
            </div>
            <div>
              <div className="text-[11px] text-slate-500 dark:text-slate-400">Failed</div>
              <div className="text-xl font-semibold font-mono text-rose-700 dark:text-rose-400">
                {counts.failed}
              </div>
            </div>
            <div>
              <div className="text-[11px] text-slate-500 dark:text-slate-400">Passed</div>
              <div className="text-xl font-semibold font-mono text-emerald-700 dark:text-emerald-400">
                {counts.passed}
              </div>
            </div>
            <div>
              <div className="text-[11px] text-slate-500 dark:text-slate-400">N/A</div>
              <div className="text-xl font-semibold font-mono text-slate-600 dark:text-slate-400">
                {counts.notApplicable}
              </div>
            </div>
          </div>
        </div>

        {/* Pass/Fail proportion bar */}
        {counts.total > 0 && (
          <div className="mt-3.5 h-2 w-full rounded-xs bg-slate-100 dark:bg-slate-800 overflow-hidden flex">
            {counts.passed > 0 && (
              <div
                className="h-full bg-emerald-600 dark:bg-emerald-500"
                style={{ width: `${(counts.passed / counts.total) * 100}%` }}
                title={`Passed: ${counts.passed}`}
              />
            )}
            {counts.failed > 0 && (
              <div
                className="h-full bg-rose-600 dark:bg-rose-500"
                style={{ width: `${(counts.failed / counts.total) * 100}%` }}
                title={`Failed: ${counts.failed}`}
              />
            )}
            {counts.notApplicable > 0 && (
              <div
                className="h-full bg-slate-400 dark:bg-slate-600"
                style={{ width: `${(counts.notApplicable / counts.total) * 100}%` }}
                title={`Not Applicable: ${counts.notApplicable}`}
              />
            )}
          </div>
        )}
      </section>

      {/* Filter bar + Checks table */}
      <section className="border border-slate-200 dark:border-slate-800 rounded-lg bg-white dark:bg-slate-900/60 overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-200 dark:border-slate-800 flex flex-wrap items-center justify-between gap-3 bg-slate-50/70 dark:bg-slate-900/80">
          <div className="flex items-center gap-1 text-xs">
            {(
              [
                { id: 'all', label: `All (${counts.total})` },
                { id: 'failed', label: `Failed (${counts.failed})` },
                { id: 'passed', label: `Passed (${counts.passed})` },
                { id: 'not applicable', label: `Not Applicable (${counts.notApplicable})` },
              ] as const
            ).map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setStatusFilter(tab.id)}
                className={`px-2.5 py-1.5 rounded-md font-medium transition-colors tabular-nums ${
                  statusFilter === tab.id
                    ? 'bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-950'
                    : 'text-slate-600 dark:text-slate-400 hover:bg-slate-200/70 dark:hover:bg-slate-800'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <input
            type="text"
            value={localQuery}
            onChange={(e) => setLocalQuery(e.target.value)}
            placeholder="Filter CIS ID, title, or remediation..."
            className="w-full sm:w-64 h-8 px-3 text-xs rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200 placeholder:text-slate-400 focus:outline-none focus:border-blue-500"
          />
        </div>

        <div className="divide-y divide-slate-100 dark:divide-slate-800/80">
          {filteredChecks.length === 0 ? (
            <div className="py-12 text-center text-xs text-slate-500 dark:text-slate-400">
              No SCA checks match this filter.
            </div>
          ) : (
            filteredChecks.map((alert) => {
              const isExpanded = expandedUid === alert.uid;
              const check = alert.sca?.check;
              return (
                <div key={alert.uid} className="text-xs">
                  <div className="px-4 py-2.5 flex items-start justify-between gap-4 hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors">
                    <button
                      type="button"
                      onClick={() => setExpandedUid(isExpanded ? null : alert.uid)}
                      className="flex items-start gap-2.5 text-left min-w-0 flex-1"
                    >
                      <span className="mt-0.5 text-slate-400 flex-shrink-0">
                        {isExpanded ? (
                          <ChevronDown className="w-3.5 h-3.5" />
                        ) : (
                          <ChevronRight className="w-3.5 h-3.5" />
                        )}
                      </span>
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-baseline gap-x-2.5 gap-y-0.5">
                          {alert.cisId && (
                            <span className="font-mono font-semibold text-slate-700 dark:text-slate-300 tabular-nums">
                              CIS {alert.cisId}
                            </span>
                          )}
                          <span className="font-medium text-slate-900 dark:text-slate-100">
                            {check?.title ?? alert.ruleDescription}
                          </span>
                        </div>
                        <div className="mt-0.5 text-[11px] text-slate-500 dark:text-slate-400 flex flex-wrap items-center gap-x-2">
                          <span className="font-mono">{alert.agentName}</span>
                          <span>·</span>
                          <span className="font-mono">Rule {alert.ruleId}</span>
                          {alert.mitreIds.length > 0 && (
                            <>
                              <span>·</span>
                              <span className="font-mono">{alert.mitreIds.slice(0, 3).join(', ')}</span>
                            </>
                          )}
                        </div>
                      </div>
                    </button>

                    <div className="flex items-center gap-3 flex-shrink-0">
                      <span
                        className={`font-medium whitespace-nowrap ${scaResultTextClass(alert.scaResult)}`}
                      >
                        {formatScaResultLabel(alert.scaResult)}
                      </span>
                      <button
                        type="button"
                        onClick={() => onInspectAlert(alert)}
                        className="text-xs font-medium text-blue-600 dark:text-blue-400 hover:underline whitespace-nowrap"
                      >
                        Inspect
                      </button>
                    </div>
                  </div>

                  {isExpanded && check && (
                    <div className="px-10 pb-4 pt-1 bg-slate-50/70 dark:bg-slate-900/40 space-y-3 border-t border-slate-100 dark:border-slate-800/70">
                      {check.reason && (
                        <p className="text-slate-600 dark:text-slate-400">
                          <span className="font-medium text-slate-800 dark:text-slate-200">
                            Reason:{' '}
                          </span>
                          {check.reason}
                        </p>
                      )}
                      {check.rationale && (
                        <p className="text-slate-600 dark:text-slate-400 leading-relaxed">
                          <span className="font-medium text-slate-800 dark:text-slate-200">
                            Rationale:{' '}
                          </span>
                          {check.rationale}
                        </p>
                      )}
                      {check.remediation && (
                        <div>
                          <div className="flex items-center justify-between mb-1">
                            <span className="font-medium text-slate-800 dark:text-slate-200">
                              Remediation
                            </span>
                            <button
                              type="button"
                              onClick={() => copyRemediation(alert.uid, check.remediation!)}
                              className="inline-flex items-center gap-1 text-[11px] font-medium text-blue-600 dark:text-blue-400 hover:underline"
                            >
                              {copiedUid === alert.uid ? (
                                <>
                                  <Check className="w-3 h-3" />
                                  Copied
                                </>
                              ) : (
                                <>
                                  <Copy className="w-3 h-3" />
                                  Copy command
                                </>
                              )}
                            </button>
                          </div>
                          <pre className="p-3 rounded-md border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 font-mono text-[11px] text-slate-800 dark:text-slate-200 whitespace-pre-wrap break-words">
                            {check.remediation}
                          </pre>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </section>
    </div>
  );
}
