import React, { useEffect, useState } from 'react';
import { Check, Copy, Filter, X } from 'lucide-react';
import { NormalizedAlert } from '../types/wazuh';
import { getSeverityLabel } from '../utils/wazuhParser';
import {
  formatDateTimeFull,
  formatScaResultLabel,
  scaResultTextClass,
  severityDotClass,
  severityTextClass,
} from '../utils/formatters';

interface AlertInspectorProps {
  alert: NormalizedAlert | null;
  useUtc: boolean;
  onClose: () => void;
  onQuickFilter: (
    type: 'ruleId' | 'agent' | 'decoder' | 'group' | 'mitre' | 'scaResult' | 'compliance',
    value: string
  ) => void;
}

type InspectorTab = 'details' | 'json';

export function AlertInspector({
  alert,
  useUtc,
  onClose,
  onQuickFilter,
}: AlertInspectorProps) {
  const [tab, setTab] = useState<InspectorTab>('details');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  useEffect(() => {
    if (!alert) return;
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [alert, onClose]);

  if (!alert) return null;

  const copyText = (key: string, text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedKey(key);
      window.setTimeout(() => setCopiedKey((prev) => (prev === key ? null : prev)), 1600);
    });
  };

  const rawJsonString = JSON.stringify(alert.raw, null, 2);

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-slate-950/40 dark:bg-slate-950/65 transition-opacity"
        onClick={onClose}
      />

      {/* Drawer panel */}
      <aside
        role="dialog"
        aria-label="Alert detail inspector"
        className="relative z-10 w-full max-w-2xl h-full bg-white dark:bg-slate-950 border-l border-slate-200 dark:border-slate-800 shadow-2xl flex flex-col"
      >
        {/* Header */}
        <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-xs">
              <span className="inline-flex items-center gap-1.5 font-mono font-semibold tabular-nums">
                <span className={`w-2 h-2 rounded-xs ${severityDotClass(alert.severity)}`} />
                <span className={severityTextClass(alert.severity)}>
                  Level {alert.level} · {getSeverityLabel(alert.severity)}
                </span>
              </span>
              <span className="text-slate-300 dark:text-slate-700">/</span>
              <span className="font-mono text-slate-600 dark:text-slate-400 tabular-nums">
                Rule {alert.ruleId}
              </span>
              {alert.scaResult && (
                <>
                  <span className="text-slate-300 dark:text-slate-700">/</span>
                  <span className={`font-medium ${scaResultTextClass(alert.scaResult)}`}>
                    {formatScaResultLabel(alert.scaResult)}
                  </span>
                </>
              )}
            </div>
            <h2 className="mt-1.5 text-base font-semibold text-slate-900 dark:text-slate-100 leading-snug">
              {alert.ruleDescription}
            </h2>
            <p className="mt-1 text-xs font-mono text-slate-500 dark:text-slate-400 tabular-nums">
              {formatDateTimeFull(alert.timestampMs, useUtc)} · ID {alert.id}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-md text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
            aria-label="Close inspector"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Sub-tabs */}
        <div className="px-5 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50/70 dark:bg-slate-900/50">
          <div className="flex items-center gap-5">
            {(
              [
                { id: 'details', label: 'Structured Details' },
                { id: 'json', label: 'Raw JSON' },
              ] as const
            ).map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => setTab(t.id)}
                className={`py-2.5 text-xs font-medium border-b-2 transition-colors ${
                  tab === t.id
                    ? 'border-blue-600 dark:border-blue-400 text-slate-900 dark:text-white'
                    : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>

          <button
            type="button"
            onClick={() => copyText('raw-json', rawJsonString)}
            className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-600 dark:text-slate-300 hover:text-slate-950 dark:hover:text-white py-1"
          >
            {copiedKey === 'raw-json' ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
                Copied JSON
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                Copy JSON
              </>
            )}
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-5">
          {tab === 'json' ? (
            <pre className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 font-mono text-[11px] leading-relaxed text-slate-800 dark:text-slate-200 overflow-x-auto whitespace-pre-wrap break-all">
              {rawJsonString}
            </pre>
          ) : (
            <>
              {/* Quick Filter Actions */}
              <div className="flex flex-wrap items-center gap-2 pb-1">
                <span className="text-[11px] text-slate-500 dark:text-slate-400 inline-flex items-center gap-1 mr-1">
                  <Filter className="w-3 h-3" />
                  Filter by:
                </span>
                <button
                  type="button"
                  onClick={() => onQuickFilter('ruleId', alert.ruleId)}
                  className="px-2 py-1 rounded-md text-xs font-mono border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 hover:border-blue-500 hover:text-blue-600 dark:hover:text-blue-400 transition-colors"
                >
                  rule:{alert.ruleId}
                </button>
                <button
                  type="button"
                  onClick={() => onQuickFilter('agent', alert.agentName)}
                  className="px-2 py-1 rounded-md text-xs font-mono border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 hover:border-blue-500 hover:text-blue-600 dark:hover:text-blue-400 transition-colors"
                >
                  agent:{alert.agentName}
                </button>
                <button
                  type="button"
                  onClick={() => onQuickFilter('decoder', alert.decoderName)}
                  className="px-2 py-1 rounded-md text-xs font-mono border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 hover:border-blue-500 hover:text-blue-600 dark:hover:text-blue-400 transition-colors"
                >
                  decoder:{alert.decoderName}
                </button>
                {alert.scaResult && (
                  <button
                    type="button"
                    onClick={() => onQuickFilter('scaResult', alert.scaResult!)}
                    className="px-2 py-1 rounded-md text-xs font-mono border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 hover:border-blue-500 hover:text-blue-600 dark:hover:text-blue-400 transition-colors"
                  >
                    sca:{alert.scaResult}
                  </button>
                )}
              </div>

              {/* Overview Key-Value Grid */}
              <section>
                <h3 className="text-xs font-semibold text-slate-900 dark:text-slate-100 mb-2">
                  Alert Metadata
                </h3>
                <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2.5 border-t border-slate-200 dark:border-slate-800 pt-3 text-xs">
                  <MetaRow label="Agent" value={`${alert.agentName} (ID ${alert.agentId})`} mono />
                  <MetaRow label="Agent IP" value={alert.agentIp} mono />
                  <MetaRow label="Manager" value={alert.managerName} mono />
                  <MetaRow label="Index" value={alert.index} mono />
                  <MetaRow
                    label="Decoder"
                    value={
                      alert.decoderParent
                        ? `${alert.decoderName} (parent: ${alert.decoderParent})`
                        : alert.decoderName
                    }
                    mono
                  />
                  <MetaRow label="Log Location" value={alert.location} mono />
                  <MetaRow label="Fired Times" value={String(alert.firedTimes)} mono />
                  {alert.programName && (
                    <MetaRow label="Program" value={alert.programName} mono />
                  )}
                </dl>

                {/* Rule groups */}
                {alert.ruleGroups.length > 0 && (
                  <div className="mt-3 pt-2.5 border-t border-slate-100 dark:border-slate-800/80 flex flex-wrap items-baseline gap-x-2 gap-y-1 text-xs">
                    <span className="text-slate-500 dark:text-slate-400">Rule Groups:</span>
                    {alert.ruleGroups.map((group, idx) => (
                      <React.Fragment key={group}>
                        {idx > 0 && <span className="text-slate-300 dark:text-slate-700">·</span>}
                        <button
                          type="button"
                          onClick={() => onQuickFilter('group', group)}
                          className="font-mono text-slate-700 dark:text-slate-300 hover:text-blue-600 dark:hover:text-blue-400 hover:underline"
                        >
                          {group}
                        </button>
                      </React.Fragment>
                    ))}
                  </div>
                )}
              </section>

              {/* Full Log */}
              {alert.fullLog && (
                <section>
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                      Full Log
                    </h3>
                    <button
                      type="button"
                      onClick={() => copyText('full-log', alert.fullLog!)}
                      className="inline-flex items-center gap-1 text-[11px] font-medium text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white"
                    >
                      {copiedKey === 'full-log' ? (
                        <>
                          <Check className="w-3 h-3 text-emerald-600" />
                          Copied
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" />
                          Copy
                        </>
                      )}
                    </button>
                  </div>
                  <pre className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 font-mono text-[11px] leading-relaxed text-slate-800 dark:text-slate-200 whitespace-pre-wrap break-all">
                    {alert.fullLog}
                  </pre>
                </section>
              )}

              {/* Sudo / PAM Event Fields */}
              {(alert.srcUser || alert.dstUser || alert.command || alert.pwd) && (
                <section>
                  <h3 className="text-xs font-semibold text-slate-900 dark:text-slate-100 mb-2">
                    Privilege & Command Context
                  </h3>
                  <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2.5 border-t border-slate-200 dark:border-slate-800 pt-3 text-xs">
                    {alert.srcUser && <MetaRow label="Source User" value={alert.srcUser} mono />}
                    {alert.dstUser && <MetaRow label="Target User" value={alert.dstUser} mono />}
                    {alert.pwd && <MetaRow label="Working Directory" value={alert.pwd} mono />}
                    {alert.command && (
                      <div className="sm:col-span-2">
                        <MetaRow label="Command" value={alert.command} mono />
                      </div>
                    )}
                  </dl>
                </section>
              )}

              {/* Dpkg Package Fields */}
              {(alert.dpkgPackage || alert.dpkgStatus || alert.dpkgVersion) && (
                <section>
                  <h3 className="text-xs font-semibold text-slate-900 dark:text-slate-100 mb-2">
                    Package Activity (dpkg)
                  </h3>
                  <dl className="grid grid-cols-1 sm:grid-cols-3 gap-x-6 gap-y-2.5 border-t border-slate-200 dark:border-slate-800 pt-3 text-xs">
                    {alert.dpkgPackage && (
                      <MetaRow label="Package" value={alert.dpkgPackage} mono />
                    )}
                    {alert.dpkgStatus && <MetaRow label="Status" value={alert.dpkgStatus} mono />}
                    {alert.dpkgVersion && (
                      <MetaRow label="Version" value={alert.dpkgVersion} mono />
                    )}
                  </dl>
                </section>
              )}

              {/* SCA Summary Details */}
              {alert.sca && alert.sca.type === 'summary' && (
                <section>
                  <h3 className="text-xs font-semibold text-slate-900 dark:text-slate-100 mb-2">
                    SCA Scan Summary
                  </h3>
                  <div className="border border-slate-200 dark:border-slate-800 rounded-lg p-3.5 bg-slate-50/70 dark:bg-slate-900/60 space-y-3 text-xs">
                    {alert.sca.policy && (
                      <div className="font-medium text-slate-900 dark:text-slate-100">
                        {alert.sca.policy}
                      </div>
                    )}
                    <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 tabular-nums">
                      <div>
                        <div className="text-[11px] text-slate-500">Score</div>
                        <div className="text-base font-semibold font-mono text-slate-900 dark:text-slate-100">
                          {alert.sca.score ?? '—'}%
                        </div>
                      </div>
                      <div>
                        <div className="text-[11px] text-slate-500">Passed</div>
                        <div className="text-base font-semibold font-mono text-emerald-700 dark:text-emerald-400">
                          {alert.sca.passed ?? 0}
                        </div>
                      </div>
                      <div>
                        <div className="text-[11px] text-slate-500">Failed</div>
                        <div className="text-base font-semibold font-mono text-rose-700 dark:text-rose-400">
                          {alert.sca.failed ?? 0}
                        </div>
                      </div>
                      <div>
                        <div className="text-[11px] text-slate-500">Invalid</div>
                        <div className="text-base font-semibold font-mono text-slate-600 dark:text-slate-400">
                          {alert.sca.invalid ?? 0}
                        </div>
                      </div>
                      <div>
                        <div className="text-[11px] text-slate-500">Total</div>
                        <div className="text-base font-semibold font-mono text-slate-900 dark:text-slate-100">
                          {alert.sca.total_checks ?? 0}
                        </div>
                      </div>
                    </div>
                    {alert.sca.description && (
                      <p className="text-slate-600 dark:text-slate-400 leading-relaxed">
                        {alert.sca.description}
                      </p>
                    )}
                  </div>
                </section>
              )}

              {/* SCA Individual Check Details */}
              {alert.sca?.check && (
                <section className="space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                      SCA Benchmark Check
                    </h3>
                    {alert.cisId && (
                      <span className="text-xs font-mono text-slate-500 dark:text-slate-400">
                        CIS {alert.cisId}
                      </span>
                    )}
                  </div>

                  <div className="border-t border-slate-200 dark:border-slate-800 pt-3 space-y-3 text-xs">
                    {alert.sca.policy && (
                      <MetaRow label="Policy" value={alert.sca.policy} />
                    )}
                    {alert.sca.check.title && (
                      <MetaRow label="Check Title" value={alert.sca.check.title} />
                    )}
                    {alert.sca.check.reason && (
                      <MetaRow label="Evaluation Reason" value={alert.sca.check.reason} />
                    )}
                    {alert.sca.check.description && (
                      <div>
                        <div className="text-[11px] text-slate-500 dark:text-slate-400 mb-1">
                          Description
                        </div>
                        <p className="text-slate-700 dark:text-slate-300 leading-relaxed whitespace-pre-line">
                          {alert.sca.check.description}
                        </p>
                      </div>
                    )}
                    {alert.sca.check.rationale && (
                      <div>
                        <div className="text-[11px] text-slate-500 dark:text-slate-400 mb-1">
                          Rationale
                        </div>
                        <p className="text-slate-700 dark:text-slate-300 leading-relaxed whitespace-pre-line">
                          {alert.sca.check.rationale}
                        </p>
                      </div>
                    )}
                    {alert.sca.check.remediation && (
                      <div>
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-[11px] text-slate-500 dark:text-slate-400">
                            Remediation
                          </span>
                          <button
                            type="button"
                            onClick={() => copyText('remediation', alert.sca!.check!.remediation!)}
                            className="inline-flex items-center gap-1 text-[11px] font-medium text-blue-600 dark:text-blue-400 hover:underline"
                          >
                            {copiedKey === 'remediation' ? (
                              <>
                                <Check className="w-3 h-3" />
                                Copied
                              </>
                            ) : (
                              <>
                                <Copy className="w-3 h-3" />
                                Copy remediation
                              </>
                            )}
                          </button>
                        </div>
                        <pre className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 font-mono text-[11px] leading-relaxed text-slate-800 dark:text-slate-200 whitespace-pre-wrap break-words">
                          {alert.sca.check.remediation}
                        </pre>
                      </div>
                    )}
                    {alert.sca.check.command && alert.sca.check.command.length > 0 && (
                      <div>
                        <div className="text-[11px] text-slate-500 dark:text-slate-400 mb-1">
                          Audit Command(s)
                        </div>
                        <pre className="p-2.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 font-mono text-[11px] text-slate-800 dark:text-slate-200 whitespace-pre-wrap break-all">
                          {alert.sca.check.command.join('\n')}
                        </pre>
                      </div>
                    )}
                    {alert.sca.check.file && alert.sca.check.file.length > 0 && (
                      <MetaRow
                        label="Checked Files"
                        value={alert.sca.check.file.join(', ')}
                        mono
                      />
                    )}
                  </div>
                </section>
              )}

              {/* MITRE ATT&CK */}
              {(alert.mitreIds.length > 0 ||
                alert.mitreTactics.length > 0 ||
                alert.mitreTechniques.length > 0) && (
                <section>
                  <h3 className="text-xs font-semibold text-slate-900 dark:text-slate-100 mb-2">
                    MITRE ATT&CK Mapping
                  </h3>
                  <dl className="space-y-2 border-t border-slate-200 dark:border-slate-800 pt-3 text-xs">
                    {alert.mitreIds.length > 0 && (
                      <div>
                        <dt className="text-[11px] text-slate-500 dark:text-slate-400 mb-0.5">
                          Technique IDs
                        </dt>
                        <dd className="flex flex-wrap items-center gap-x-2 gap-y-1">
                          {alert.mitreIds.map((id, i) => (
                            <React.Fragment key={id}>
                              {i > 0 && <span className="text-slate-300 dark:text-slate-700">·</span>}
                              <button
                                type="button"
                                onClick={() => onQuickFilter('mitre', id)}
                                className="font-mono text-blue-700 dark:text-blue-400 hover:underline"
                              >
                                {id}
                              </button>
                            </React.Fragment>
                          ))}
                        </dd>
                      </div>
                    )}
                    {alert.mitreTactics.length > 0 && (
                      <MetaRow label="Tactics" value={alert.mitreTactics.join(' · ')} />
                    )}
                    {alert.mitreTechniques.length > 0 && (
                      <MetaRow label="Techniques" value={alert.mitreTechniques.join(' · ')} />
                    )}
                  </dl>
                </section>
              )}

              {/* Compliance Frameworks */}
              {alert.complianceFrameworks.length > 0 && (
                <section>
                  <h3 className="text-xs font-semibold text-slate-900 dark:text-slate-100 mb-2">
                    Compliance Controls
                  </h3>
                  <dl className="divide-y divide-slate-100 dark:divide-slate-800/80 border-t border-slate-200 dark:border-slate-800 text-xs">
                    {Object.entries(alert.compliance).map(([framework, controls]) => (
                      <div key={framework} className="py-2 flex items-baseline justify-between gap-4">
                        <dt className="flex-shrink-0">
                          <button
                            type="button"
                            onClick={() => onQuickFilter('compliance', framework)}
                            className="font-medium text-slate-700 dark:text-slate-300 hover:text-blue-600 dark:hover:text-blue-400 hover:underline"
                          >
                            {framework}
                          </button>
                        </dt>
                        <dd className="font-mono text-[11px] text-slate-600 dark:text-slate-400 text-right break-words">
                          {controls.join(', ')}
                        </dd>
                      </div>
                    ))}
                  </dl>
                </section>
              )}
            </>
          )}
        </div>
      </aside>
    </div>
  );
}

function MetaRow({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] text-slate-500 dark:text-slate-400">{label}</dt>
      <dd
        className={`mt-0.5 text-slate-800 dark:text-slate-200 break-words ${
          mono ? 'font-mono text-[11px]' : ''
        }`}
      >
        {value}
      </dd>
    </div>
  );
}
