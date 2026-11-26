import React, { useState } from 'react';
import { ChevronDown, ChevronRight, RotateCcw, X } from 'lucide-react';
import { DashboardFacets, FacetItem, FilterState, SeverityBand } from '../types/wazuh';
import { getSeverityLabel } from '../utils/wazuhParser';
import {
  formatScaResultLabel,
  formatTimeSpan,
  scaResultTextClass,
  severityDotClass,
  severityTextClass,
} from '../utils/formatters';

interface SidebarFacetsProps {
  facets: DashboardFacets;
  filters: FilterState;
  totalAlerts: number;
  filteredCount: number;
  formatDetected: string;
  timeSpan: [number, number] | null;
  hasActive: boolean;
  onToggleSeverity: (band: SeverityBand) => void;
  onLevelChange: (min: number, max: number) => void;
  onToggleFacet: (
    key: 'agents' | 'decoders' | 'groups' | 'scaResults' | 'mitreItems' | 'complianceFrameworks',
    value: string
  ) => void;
  onResetFilters: () => void;
  isOpenMobile: boolean;
  onCloseMobile: () => void;
}

const SEVERITY_ORDER: Array<{ band: SeverityBand; range: string }> = [
  { band: 'critical', range: '12–15' },
  { band: 'high', range: '8–11' },
  { band: 'medium', range: '4–7' },
  { band: 'low', range: '0–3' },
];

interface CollapsibleSectionProps {
  title: string;
  selectedCount?: number;
  defaultOpen?: boolean;
  children: React.ReactNode;
}

function CollapsibleSection({
  title,
  selectedCount = 0,
  defaultOpen = true,
  children,
}: CollapsibleSectionProps) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <div className="border-b border-slate-200 dark:border-slate-800 py-3">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between text-left px-4 py-1 text-xs font-semibold text-slate-800 dark:text-slate-200 hover:text-slate-950 dark:hover:text-white transition-colors"
      >
        <span className="flex items-center gap-1.5">
          {open ? (
            <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
          ) : (
            <ChevronRight className="w-3.5 h-3.5 text-slate-400" />
          )}
          <span>{title}</span>
        </span>
        {selectedCount > 0 && (
          <span className="text-[11px] font-medium text-blue-600 dark:text-blue-400 tabular-nums">
            {selectedCount} active
          </span>
        )}
      </button>
      {open && <div className="mt-1.5 px-3 space-y-0.5">{children}</div>}
    </div>
  );
}

interface FacetListProps {
  items: FacetItem[];
  selected: string[];
  onToggle: (value: string) => void;
  initialLimit?: number;
  formatLabel?: (value: string) => string;
  labelClassName?: (value: string) => string;
  monoLabel?: boolean;
}

function FacetList({
  items,
  selected,
  onToggle,
  initialLimit = 6,
  formatLabel,
  labelClassName,
  monoLabel = false,
}: FacetListProps) {
  const [expanded, setExpanded] = useState(false);

  if (items.length === 0) {
    return (
      <p className="px-2 py-1 text-xs text-slate-400 dark:text-slate-500">
        No values in current view
      </p>
    );
  }

  const visible = expanded ? items : items.slice(0, initialLimit);
  const remaining = items.length - visible.length;

  return (
    <>
      {visible.map((item) => {
        const checked = selected.includes(item.value);
        const displayLabel = formatLabel ? formatLabel(item.label) : item.label;
        const customColor = labelClassName ? labelClassName(item.value) : '';
        return (
          <button
            key={item.value}
            type="button"
            onClick={() => onToggle(item.value)}
            className={`w-full flex items-center justify-between gap-2 px-2 py-1.5 rounded-md text-xs transition-colors text-left ${
              checked
                ? 'bg-blue-50 dark:bg-blue-950/60 text-blue-900 dark:text-blue-100 font-medium'
                : 'text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800/70'
            }`}
          >
            <span className="flex items-center gap-2 min-w-0">
              <span
                className={`w-3.5 h-3.5 rounded border flex-shrink-0 flex items-center justify-center ${
                  checked
                    ? 'bg-blue-600 border-blue-600 text-white'
                    : 'border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900'
                }`}
              >
                {checked && (
                  <svg className="w-2.5 h-2.5" viewBox="0 0 12 12" fill="none">
                    <path
                      d="M2.5 6L5 8.5L9.5 3.5"
                      stroke="currentColor"
                      strokeWidth="1.75"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                )}
              </span>
              <span className="truncate">
                <span
                  className={`${monoLabel ? 'font-mono text-[11px]' : ''} ${
                    checked ? '' : customColor
                  }`}
                >
                  {displayLabel}
                </span>
                {item.sublabel && item.sublabel !== '—' && (
                  <span className="block text-[11px] font-mono text-slate-400 dark:text-slate-500 truncate">
                    {item.sublabel}
                  </span>
                )}
              </span>
            </span>
            <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400 tabular-nums flex-shrink-0">
              {item.count.toLocaleString()}
            </span>
          </button>
        );
      })}
      {items.length > initialLimit && (
        <button
          type="button"
          onClick={() => setExpanded((e) => !e)}
          className="px-2 pt-1 text-[11px] font-medium text-blue-600 dark:text-blue-400 hover:underline"
        >
          {expanded ? 'Show fewer' : `Show ${remaining} more`}
        </button>
      )}
    </>
  );
}

export function SidebarFacets({
  facets,
  filters,
  totalAlerts,
  filteredCount,
  formatDetected,
  timeSpan,
  hasActive,
  onToggleSeverity,
  onLevelChange,
  onToggleFacet,
  onResetFilters,
  isOpenMobile,
  onCloseMobile,
}: SidebarFacetsProps) {
  const sidebarBody = (
    <div className="flex flex-col h-full bg-slate-50/70 dark:bg-slate-950 border-r border-slate-200 dark:border-slate-800">
      {/* Dataset overview header */}
      <div className="px-4 py-3 border-b border-slate-200 dark:border-slate-800">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold text-slate-900 dark:text-slate-100">
            Filters
          </span>
          <div className="flex items-center gap-2">
            {hasActive && (
              <button
                type="button"
                onClick={onResetFilters}
                className="inline-flex items-center gap-1 text-xs font-medium text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300"
              >
                <RotateCcw className="w-3 h-3" />
                Reset
              </button>
            )}
            <button
              type="button"
              onClick={onCloseMobile}
              className="lg:hidden p-1 text-slate-500 hover:text-slate-900 dark:hover:text-white"
              aria-label="Close filters"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>
        <div className="mt-2 space-y-1 text-[11px] text-slate-500 dark:text-slate-400">
          <div className="flex items-center justify-between">
            <span>Showing</span>
            <span className="font-mono tabular-nums text-slate-700 dark:text-slate-300">
              {filteredCount.toLocaleString()} / {totalAlerts.toLocaleString()}
            </span>
          </div>
          {timeSpan && (
            <div className="flex items-center justify-between">
              <span>Window</span>
              <span className="font-mono tabular-nums text-slate-700 dark:text-slate-300">
                {formatTimeSpan(timeSpan[0], timeSpan[1])}
              </span>
            </div>
          )}
          {formatDetected && (
            <div className="flex items-center justify-between gap-2">
              <span>Source</span>
              <span className="truncate text-slate-600 dark:text-slate-400" title={formatDetected}>
                {formatDetected}
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Scrollable facets */}
      <div className="flex-1 overflow-y-auto">
        {/* Severity & Numeric Level */}
        <CollapsibleSection
          title="Severity & Level"
          selectedCount={
            filters.severities.length + (filters.minLevel > 0 || filters.maxLevel < 15 ? 1 : 0)
          }
          defaultOpen
        >
          {SEVERITY_ORDER.map(({ band, range }) => {
            const count = facets.severities[band];
            const checked = filters.severities.includes(band);
            return (
              <button
                key={band}
                type="button"
                onClick={() => onToggleSeverity(band)}
                className={`w-full flex items-center justify-between gap-2 px-2 py-1.5 rounded-md text-xs transition-colors ${
                  checked
                    ? 'bg-blue-50 dark:bg-blue-950/60 text-blue-900 dark:text-blue-100 font-medium'
                    : 'text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800/70'
                }`}
              >
                <span className="flex items-center gap-2">
                  <span className={`w-2 h-2 rounded-xs flex-shrink-0 ${severityDotClass(band)}`} />
                  <span className={checked ? '' : severityTextClass(band)}>
                    {getSeverityLabel(band)}
                  </span>
                  <span className="text-[11px] font-mono text-slate-400 dark:text-slate-500">
                    L{range}
                  </span>
                </span>
                <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400 tabular-nums">
                  {count.toLocaleString()}
                </span>
              </button>
            );
          })}

          <div className="pt-2.5 pb-1 px-1 grid grid-cols-2 gap-2">
            <label className="block">
              <span className="block text-[11px] text-slate-500 dark:text-slate-400 mb-1">
                Min level
              </span>
              <select
                value={filters.minLevel}
                onChange={(e) => {
                  const nextMin = Number(e.target.value);
                  onLevelChange(nextMin, Math.max(nextMin, filters.maxLevel));
                }}
                className="w-full h-7 px-2 text-xs font-mono tabular-nums rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200 focus:outline-none focus:border-blue-500"
              >
                {Array.from({ length: 16 }, (_, i) => (
                  <option key={i} value={i}>
                    {i}
                  </option>
                ))}
              </select>
            </label>
            <label className="block">
              <span className="block text-[11px] text-slate-500 dark:text-slate-400 mb-1">
                Max level
              </span>
              <select
                value={filters.maxLevel}
                onChange={(e) => {
                  const nextMax = Number(e.target.value);
                  onLevelChange(Math.min(filters.minLevel, nextMax), nextMax);
                }}
                className="w-full h-7 px-2 text-xs font-mono tabular-nums rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200 focus:outline-none focus:border-blue-500"
              >
                {Array.from({ length: 16 }, (_, i) => (
                  <option key={i} value={i}>
                    {i}
                  </option>
                ))}
              </select>
            </label>
          </div>
        </CollapsibleSection>

        {/* Agents */}
        <CollapsibleSection title="Agents" selectedCount={filters.agents.length} defaultOpen>
          <FacetList
            items={facets.agents}
            selected={filters.agents}
            onToggle={(v) => onToggleFacet('agents', v)}
          />
        </CollapsibleSection>

        {/* Decoders */}
        <CollapsibleSection title="Decoders" selectedCount={filters.decoders.length} defaultOpen>
          <FacetList
            items={facets.decoders}
            selected={filters.decoders}
            onToggle={(v) => onToggleFacet('decoders', v)}
            monoLabel
          />
        </CollapsibleSection>

        {/* Rule Groups */}
        <CollapsibleSection title="Rule Groups" selectedCount={filters.groups.length} defaultOpen>
          <FacetList
            items={facets.groups}
            selected={filters.groups}
            onToggle={(v) => onToggleFacet('groups', v)}
            initialLimit={7}
          />
        </CollapsibleSection>

        {/* SCA Result (when present) */}
        {facets.scaResults.length > 0 && (
          <CollapsibleSection
            title="SCA Check Result"
            selectedCount={filters.scaResults.length}
            defaultOpen
          >
            <FacetList
              items={facets.scaResults}
              selected={filters.scaResults}
              onToggle={(v) => onToggleFacet('scaResults', v)}
              formatLabel={formatScaResultLabel}
              labelClassName={scaResultTextClass}
            />
          </CollapsibleSection>
        )}

        {/* MITRE ATT&CK */}
        {facets.mitreItems.length > 0 && (
          <CollapsibleSection
            title="MITRE ATT&CK"
            selectedCount={filters.mitreItems.length}
            defaultOpen={false}
          >
            <FacetList
              items={facets.mitreItems}
              selected={filters.mitreItems}
              onToggle={(v) => onToggleFacet('mitreItems', v)}
              initialLimit={8}
              monoLabel
            />
          </CollapsibleSection>
        )}

        {/* Compliance */}
        {facets.complianceFrameworks.length > 0 && (
          <CollapsibleSection
            title="Compliance"
            selectedCount={filters.complianceFrameworks.length}
            defaultOpen={false}
          >
            <FacetList
              items={facets.complianceFrameworks}
              selected={filters.complianceFrameworks}
              onToggle={(v) => onToggleFacet('complianceFrameworks', v)}
              initialLimit={8}
            />
          </CollapsibleSection>
        )}
      </div>
    </div>
  );

  return (
    <>
      {/* Desktop persistent left rail */}
      <aside className="hidden lg:block w-[260px] flex-shrink-0 h-full overflow-hidden">
        {sidebarBody}
      </aside>

      {/* Mobile slide-over drawer */}
      {isOpenMobile && (
        <div className="fixed inset-0 z-40 lg:hidden flex">
          <div
            className="fixed inset-0 bg-slate-950/50 backdrop-blur-[1px]"
            onClick={onCloseMobile}
          />
          <div className="relative z-10 w-[280px] max-w-[85vw] h-full shadow-xl">
            {sidebarBody}
          </div>
        </div>
      )}
    </>
  );
}
