import React, { useEffect } from 'react';
import { ArrowDown, ArrowUp, ArrowUpDown, ChevronLeft, ChevronRight, SearchX } from 'lucide-react';
import { NormalizedAlert, SortDirection, SortField } from '../types/wazuh';
import { getSeverityLabel } from '../utils/wazuhParser';
import {
  formatDateShort,
  formatScaResultLabel,
  formatTimeShort,
  scaResultTextClass,
  severityDotClass,
  severityTextClass,
} from '../utils/formatters';

interface AlertTableProps {
  alerts: NormalizedAlert[];
  totalFiltered: number;
  page: number;
  pageSize: number;
  sortField: SortField;
  sortDirection: SortDirection;
  selectedAlertUid: string | null;
  useUtc: boolean;
  hasActiveFilters: boolean;
  onSortChange: (field: SortField) => void;
  onSelectAlert: (alert: NormalizedAlert) => void;
  onPageChange: (page: number) => void;
  onPageSizeChange: (size: number) => void;
  onClearFilters: () => void;
}

function getAlertSubtext(alert: NormalizedAlert): string | null {
  if (alert.sca?.type === 'summary' && alert.sca.score !== undefined) {
    return `Score ${alert.sca.score}% · ${alert.sca.passed ?? 0} passed · ${alert.sca.failed ?? 0} failed`;
  }
  if (alert.sca?.check?.title) {
    const prefix = alert.cisId ? `CIS ${alert.cisId} · ` : '';
    return `${prefix}${alert.sca.check.title}`;
  }
  if (alert.command) {
    const userInfo = alert.srcUser ? `${alert.srcUser}→${alert.dstUser ?? 'root'}: ` : '';
    return `${userInfo}${alert.command}`;
  }
  if (alert.dpkgPackage) {
    return `${alert.dpkgPackage}${alert.dpkgVersion ? ` (${alert.dpkgVersion})` : ''}${alert.dpkgStatus ? ` · ${alert.dpkgStatus}` : ''}`;
  }
  if (alert.fullLog) {
    return alert.fullLog;
  }
  return null;
}

export function AlertTable({
  alerts,
  totalFiltered,
  page,
  pageSize,
  sortField,
  sortDirection,
  selectedAlertUid,
  useUtc,
  hasActiveFilters,
  onSortChange,
  onSelectAlert,
  onPageChange,
  onPageSizeChange,
  onClearFilters,
}: AlertTableProps) {
  const totalPages = Math.max(1, Math.ceil(totalFiltered / pageSize));
  const startIdx = totalFiltered === 0 ? 0 : (page - 1) * pageSize + 1;
  const endIdx = Math.min(totalFiltered, page * pageSize);

  // Keyboard arrow navigation when an alert is selected
  useEffect(() => {
    if (!selectedAlertUid || alerts.length === 0) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      if (
        target &&
        (target.tagName === 'INPUT' ||
          target.tagName === 'TEXTAREA' ||
          target.tagName === 'SELECT')
      ) {
        return;
      }
      if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;

      const idx = alerts.findIndex((a) => a.uid === selectedAlertUid);
      if (idx === -1) return;
      e.preventDefault();
      const nextIdx = e.key === 'ArrowDown' ? Math.min(alerts.length - 1, idx + 1) : Math.max(0, idx - 1);
      if (nextIdx !== idx) {
        onSelectAlert(alerts[nextIdx]);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [alerts, selectedAlertUid, onSelectAlert]);

  const renderSortIcon = (field: SortField) => {
    if (sortField !== field) {
      return <ArrowUpDown className="w-3 h-3 text-slate-400 opacity-60" />;
    }
    return sortDirection === 'asc' ? (
      <ArrowUp className="w-3 h-3 text-blue-600 dark:text-blue-400" />
    ) : (
      <ArrowDown className="w-3 h-3 text-blue-600 dark:text-blue-400" />
    );
  };

  if (totalFiltered === 0) {
    return (
      <div className="border border-slate-200 dark:border-slate-800 rounded-lg bg-white dark:bg-slate-900/60 py-16 px-6 text-center">
        <SearchX className="w-8 h-8 text-slate-400 dark:text-slate-500 mx-auto mb-3" />
        <p className="text-sm font-medium text-slate-800 dark:text-slate-200">
          No alerts match your current filters
        </p>
        <p className="mt-1 text-xs text-slate-500 dark:text-slate-400 max-w-md mx-auto">
          Try relaxing your search query, expanding the level range, or resetting active facet filters.
        </p>
        {hasActiveFilters && (
          <button
            type="button"
            onClick={onClearFilters}
            className="mt-4 inline-flex items-center px-3 py-1.5 rounded-md text-xs font-medium bg-blue-600 text-white hover:bg-blue-700 transition-colors"
          >
            Clear all filters
          </button>
        )}
      </div>
    );
  }

  return (
    <div className="border border-slate-200 dark:border-slate-800 rounded-lg bg-white dark:bg-slate-900/60 overflow-hidden flex flex-col">
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-left">
          <thead className="bg-slate-50 dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 sticky top-0 z-10">
            <tr className="text-[11px] font-semibold text-slate-500 dark:text-slate-400">
              <th className="py-2.5 pl-4 pr-3 whitespace-nowrap w-[152px]">
                <button
                  type="button"
                  onClick={() => onSortChange('timestampMs')}
                  className="inline-flex items-center gap-1 hover:text-slate-900 dark:hover:text-slate-100"
                >
                  Timestamp ({useUtc ? 'UTC' : 'Local'})
                  {renderSortIcon('timestampMs')}
                </button>
              </th>
              <th className="py-2.5 px-3 whitespace-nowrap w-[116px]">
                <button
                  type="button"
                  onClick={() => onSortChange('level')}
                  className="inline-flex items-center gap-1 hover:text-slate-900 dark:hover:text-slate-100"
                >
                  Level
                  {renderSortIcon('level')}
                </button>
              </th>
              <th className="py-2.5 px-3 whitespace-nowrap w-[84px]">
                <button
                  type="button"
                  onClick={() => onSortChange('ruleId')}
                  className="inline-flex items-center gap-1 hover:text-slate-900 dark:hover:text-slate-100"
                >
                  Rule ID
                  {renderSortIcon('ruleId')}
                </button>
              </th>
              <th className="py-2.5 px-3 whitespace-nowrap w-[140px]">
                <button
                  type="button"
                  onClick={() => onSortChange('agentName')}
                  className="inline-flex items-center gap-1 hover:text-slate-900 dark:hover:text-slate-100"
                >
                  Agent
                  {renderSortIcon('agentName')}
                </button>
              </th>
              <th className="py-2.5 px-3 whitespace-nowrap w-[150px]">
                <button
                  type="button"
                  onClick={() => onSortChange('decoderName')}
                  className="inline-flex items-center gap-1 hover:text-slate-900 dark:hover:text-slate-100"
                >
                  Decoder / Group
                  {renderSortIcon('decoderName')}
                </button>
              </th>
              <th className="py-2.5 pl-3 pr-4">Description</th>
            </tr>
          </thead>

          <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80 text-xs">
            {alerts.map((alert) => {
              const isSelected = alert.uid === selectedAlertUid;
              const subtext = getAlertSubtext(alert);
              const primaryGroups = alert.ruleGroups.slice(0, 2).join(' · ');

              return (
                <tr
                  key={alert.uid}
                  onClick={() => onSelectAlert(alert)}
                  tabIndex={0}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      onSelectAlert(alert);
                    }
                  }}
                  className={`cursor-pointer transition-colors focus:outline-none ${
                    isSelected
                      ? 'bg-blue-50/90 dark:bg-blue-950/50'
                      : 'hover:bg-slate-50 dark:hover:bg-slate-800/50'
                  }`}
                >
                  {/* Timestamp */}
                  <td className="py-2 pl-4 pr-3 align-top whitespace-nowrap font-mono tabular-nums">
                    <div className="text-slate-800 dark:text-slate-200 text-[12px]">
                      {formatTimeShort(alert.timestampMs, useUtc)}
                    </div>
                    <div className="text-[10px] text-slate-400 dark:text-slate-500">
                      {formatDateShort(alert.timestampMs, useUtc)}
                    </div>
                  </td>

                  {/* Level & Severity (no pill capsule; explicit indicator + number + label) */}
                  <td className="py-2 px-3 align-top whitespace-nowrap">
                    <div className="flex items-center gap-1.5">
                      <span
                        className={`w-2 h-2 rounded-xs flex-shrink-0 ${severityDotClass(alert.severity)}`}
                      />
                      <span
                        className={`font-mono font-semibold tabular-nums ${severityTextClass(alert.severity)}`}
                      >
                        L{alert.level}
                      </span>
                      <span className={`text-[11px] ${severityTextClass(alert.severity)}`}>
                        {getSeverityLabel(alert.severity)}
                      </span>
                    </div>
                  </td>

                  {/* Rule ID */}
                  <td className="py-2 px-3 align-top whitespace-nowrap font-mono tabular-nums text-slate-700 dark:text-slate-300">
                    {alert.ruleId}
                  </td>

                  {/* Agent */}
                  <td className="py-2 px-3 align-top whitespace-nowrap">
                    <div className="text-slate-800 dark:text-slate-200 font-medium truncate max-w-[132px]">
                      {alert.agentName}
                    </div>
                    <div className="text-[10px] font-mono tabular-nums text-slate-400 dark:text-slate-500">
                      {alert.agentIp}
                    </div>
                  </td>

                  {/* Decoder / Groups */}
                  <td className="py-2 px-3 align-top whitespace-nowrap">
                    <div className="font-mono text-[11px] text-slate-700 dark:text-slate-300 truncate max-w-[140px]">
                      {alert.decoderName}
                    </div>
                    {primaryGroups && (
                      <div className="text-[11px] text-slate-400 dark:text-slate-500 truncate max-w-[140px]">
                        {primaryGroups}
                      </div>
                    )}
                  </td>

                  {/* Description & contextual detail */}
                  <td className="py-2 pl-3 pr-4 align-top max-w-[460px]">
                    <div className="flex items-baseline gap-2">
                      <span className="text-slate-900 dark:text-slate-100 font-medium truncate">
                        {alert.ruleDescription}
                      </span>
                      {alert.scaResult && (
                        <span
                          className={`text-[11px] font-medium whitespace-nowrap flex-shrink-0 ${scaResultTextClass(alert.scaResult)}`}
                        >
                          · {formatScaResultLabel(alert.scaResult)}
                        </span>
                      )}
                    </div>
                    {subtext && (
                      <div className="text-[11px] text-slate-500 dark:text-slate-400 truncate mt-0.5 font-mono">
                        {subtext}
                      </div>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 border-t border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-900/80 text-xs text-slate-600 dark:text-slate-400">
        <div className="flex items-center gap-3 tabular-nums">
          <span>
            Showing <strong className="font-semibold text-slate-800 dark:text-slate-200">{startIdx.toLocaleString()}</strong>–
            <strong className="font-semibold text-slate-800 dark:text-slate-200">{endIdx.toLocaleString()}</strong> of{' '}
            <strong className="font-semibold text-slate-800 dark:text-slate-200">{totalFiltered.toLocaleString()}</strong>
          </span>

          <label className="inline-flex items-center gap-1.5">
            <span className="text-slate-500 dark:text-slate-400">Rows:</span>
            <select
              value={pageSize}
              onChange={(e) => onPageSizeChange(Number(e.target.value))}
              className="h-7 px-2 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200 font-mono text-xs focus:outline-none focus:border-blue-500"
            >
              {[25, 50, 100, 250].map((size) => (
                <option key={size} value={size}>
                  {size}
                </option>
              ))}
            </select>
          </label>
        </div>

        <div className="flex items-center gap-1.5 tabular-nums">
          <button
            type="button"
            disabled={page <= 1}
            onClick={() => onPageChange(page - 1)}
            className="inline-flex items-center gap-1 h-7 px-2.5 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            <ChevronLeft className="w-3.5 h-3.5" />
            Prev
          </button>
          <span className="px-2 font-mono text-xs text-slate-700 dark:text-slate-300">
            {page} / {totalPages}
          </span>
          <button
            type="button"
            disabled={page >= totalPages}
            onClick={() => onPageChange(page + 1)}
            className="inline-flex items-center gap-1 h-7 px-2.5 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            Next
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
}
