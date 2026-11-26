import { SeverityBand } from '../types/wazuh';

export function formatTimeShort(ms: number, useUtc = true): string {
  if (!ms) return '—';
  const d = new Date(ms);
  const pad2 = (n: number) => String(n).padStart(2, '0');
  const pad3 = (n: number) => String(n).padStart(3, '0');
  if (useUtc) {
    return `${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())}.${pad3(d.getUTCMilliseconds())}`;
  }
  return `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}.${pad3(d.getMilliseconds())}`;
}

export function formatDateShort(ms: number, useUtc = true): string {
  if (!ms) return '—';
  const d = new Date(ms);
  const pad2 = (n: number) => String(n).padStart(2, '0');
  if (useUtc) {
    return `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())}`;
  }
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
}

export function formatDateTimeFull(ms: number, useUtc = true): string {
  if (!ms) return '—';
  return `${formatDateShort(ms, useUtc)} ${formatTimeShort(ms, useUtc)}${useUtc ? ' UTC' : ''}`;
}

export function formatTimeSpan(minMs: number, maxMs: number): string {
  if (!minMs || !maxMs || maxMs < minMs) return '—';
  const diffSec = Math.max(0, Math.round((maxMs - minMs) / 1000));
  if (diffSec < 60) return `${diffSec}s window`;
  const mins = Math.floor(diffSec / 60);
  const secs = diffSec % 60;
  if (mins < 60) return secs > 0 ? `${mins}m ${secs}s` : `${mins}m`;
  const hrs = Math.floor(mins / 60);
  const remMins = mins % 60;
  if (hrs < 24) return remMins > 0 ? `${hrs}h ${remMins}m` : `${hrs}h`;
  const days = Math.floor(hrs / 24);
  const remHrs = hrs % 24;
  return remHrs > 0 ? `${days}d ${remHrs}h` : `${days}d`;
}

export function severityTextClass(band: SeverityBand): string {
  switch (band) {
    case 'critical':
      return 'text-rose-700 dark:text-rose-400';
    case 'high':
      return 'text-orange-700 dark:text-orange-400';
    case 'medium':
      return 'text-amber-700 dark:text-amber-400';
    case 'low':
      return 'text-slate-600 dark:text-slate-400';
  }
}

export function severityBarFill(band: SeverityBand): string {
  switch (band) {
    case 'critical':
      return '#e11d48';
    case 'high':
      return '#ea580c';
    case 'medium':
      return '#d97706';
    case 'low':
      return '#64748b';
  }
}

export function severityDotClass(band: SeverityBand): string {
  switch (band) {
    case 'critical':
      return 'bg-rose-600 dark:bg-rose-500';
    case 'high':
      return 'bg-orange-600 dark:bg-orange-500';
    case 'medium':
      return 'bg-amber-500 dark:bg-amber-400';
    case 'low':
      return 'bg-slate-400 dark:bg-slate-500';
  }
}

export function scaResultTextClass(result?: string): string {
  const val = (result ?? '').toLowerCase();
  if (val === 'failed') return 'text-rose-700 dark:text-rose-400';
  if (val === 'passed') return 'text-emerald-700 dark:text-emerald-400';
  if (val === 'summary') return 'text-blue-700 dark:text-blue-400';
  return 'text-slate-500 dark:text-slate-400';
}

export function formatScaResultLabel(result?: string): string {
  if (!result) return '—';
  const val = result.toLowerCase();
  if (val === 'failed') return 'Failed';
  if (val === 'passed') return 'Passed';
  if (val === 'not applicable') return 'Not Applicable';
  if (val === 'summary') return 'Scan Summary';
  return result.charAt(0).toUpperCase() + result.slice(1);
}
