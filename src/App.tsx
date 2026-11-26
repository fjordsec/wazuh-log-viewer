import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertCircle,
  Clock,
  Download,
  HelpCircle,
  Moon,
  Search,
  Shield,
  SlidersHorizontal,
  Sun,
  Upload,
  X,
} from 'lucide-react';
import {
  FilterState,
  INITIAL_FILTER_STATE,
  NormalizedAlert,
  SeverityBand,
  SortDirection,
  SortField,
} from './types/wazuh';
import { getSeverityLabel, parseWazuhFileContent } from './utils/wazuhParser';
import {
  computeFacets,
  exportAlertsToCsv,
  exportAlertsToJson,
  filterAlerts,
  hasActiveFilters,
  sortAlerts,
} from './utils/filterEngine';
import { formatTimeShort, formatScaResultLabel } from './utils/formatters';
import { SidebarFacets } from './components/SidebarFacets';
import { AlertHistogram } from './components/AlertHistogram';
import { AlertTable } from './components/AlertTable';
import { AlertInspector } from './components/AlertInspector';
import { AnalyticsView } from './components/AnalyticsView';
import { ScaView } from './components/ScaView';
import { UploadModal } from './components/UploadModal';

type NavTab = 'events' | 'analytics' | 'sca';

const SAMPLE_FILE_URL = `${import.meta.env.BASE_URL}sample-alerts.json`;
const SAMPLE_FILE_NAME = 'sample-alerts.json';

function toggleInArray<T>(list: T[], value: T): T[] {
  return list.includes(value) ? list.filter((item) => item !== value) : [...list, value];
}

export default function App() {
  // Dataset state
  const [alerts, setAlerts] = useState<NormalizedAlert[]>([]);
  const [sourceName, setSourceName] = useState<string>(SAMPLE_FILE_NAME);
  const [formatDetected, setFormatDetected] = useState<string>('');
  const [totalReported, setTotalReported] = useState<number | undefined>(undefined);
  const [loading, setLoading] = useState<boolean>(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // Navigation & UI state
  const [activeTab, setActiveTab] = useState<NavTab>('events');
  const [filters, setFilters] = useState<FilterState>(INITIAL_FILTER_STATE);
  const [sortField, setSortField] = useState<SortField>('timestampMs');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');
  const [page, setPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(50);
  const [selectedAlert, setSelectedAlert] = useState<NormalizedAlert | null>(null);
  const [isUploadOpen, setIsUploadOpen] = useState<boolean>(false);
  const [isMobileSidebarOpen, setIsMobileSidebarOpen] = useState<boolean>(false);
  const [showQueryHelp, setShowQueryHelp] = useState<boolean>(false);
  const [useUtc, setUseUtc] = useState<boolean>(true);
  const [isGlobalDragging, setIsGlobalDragging] = useState<boolean>(false);

  // Theme state (defaults to dark for security console clarity, persisted in localStorage)
  const [darkMode, setDarkMode] = useState<boolean>(() => {
    if (typeof window === 'undefined') return true;
    const saved = window.localStorage.getItem('wazuh-lens-theme');
    if (saved === 'light') return false;
    if (saved === 'dark') return true;
    return true;
  });

  const searchInputRef = useRef<HTMLInputElement>(null);
  const dragDepthRef = useRef<number>(0);

  useEffect(() => {
    const root = document.documentElement;
    if (darkMode) {
      root.classList.add('dark');
      window.localStorage.setItem('wazuh-lens-theme', 'dark');
    } else {
      root.classList.remove('dark');
      window.localStorage.setItem('wazuh-lens-theme', 'light');
    }
  }, [darkMode]);

  const loadSampleFile = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    setNotice(null);
    try {
      const response = await fetch(SAMPLE_FILE_URL);
      if (!response.ok) {
        throw new Error(`Could not fetch sample dataset (HTTP ${response.status}).`);
      }
      const text = await response.text();
      const parsed = parseWazuhFileContent(text);
      setAlerts(parsed.alerts);
      setSourceName(SAMPLE_FILE_NAME);
      setFormatDetected(parsed.formatDetected);
      setTotalReported(parsed.totalReportedInFile);
      setFilters(INITIAL_FILTER_STATE);
      setPage(1);
      setSelectedAlert(null);
    } catch (err) {
      setLoadError(
        err instanceof Error ? err.message : 'Unable to load the sample wazuh-alerts.json file.'
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadSampleFile();
  }, [loadSampleFile]);

  // Focus search bar on `/`
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const isInput =
        target &&
        (target.tagName === 'INPUT' ||
          target.tagName === 'TEXTAREA' ||
          target.tagName === 'SELECT');
      if (e.key === '/' && !isInput && !isUploadOpen) {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [isUploadOpen]);

  const handleFilesLoaded = useCallback(
    async (files: Array<{ name: string; content: string }>, mode: 'replace' | 'append') => {
      const aggregated: NormalizedAlert[] = [];
      let totalSkipped = 0;
      let detected = '';
      let reportedTotal: number | undefined = undefined;

      for (let i = 0; i < files.length; i++) {
        const res = parseWazuhFileContent(files[i].content);
        if (!detected) detected = res.formatDetected;
        if (files.length === 1) reportedTotal = res.totalReportedInFile;
        totalSkipped += res.skippedLines;

        // Guarantee unique UIDs across multi-file loads or appends
        const prefix = `${Date.now()}-${i}`;
        for (const a of res.alerts) {
          aggregated.push({ ...a, uid: `${prefix}-${a.uid}` });
        }
      }

      if (aggregated.length === 0) {
        throw new Error('No alert records were found in the uploaded file.');
      }

      setLoadError(null);
      if (mode === 'append') {
        setAlerts((prev) => [...prev, ...aggregated]);
        setSourceName((prev) =>
          files.length === 1 ? `${prev} + ${files[0].name}` : `${prev} + ${files.length} files`
        );
        setTotalReported(undefined);
        setNotice(
          `Appended ${aggregated.length.toLocaleString()} alert${aggregated.length === 1 ? '' : 's'}${
            totalSkipped > 0 ? ` (${totalSkipped} non-JSON lines skipped)` : ''
          }.`
        );
      } else {
        setAlerts(aggregated);
        setSourceName(
          files.length === 1 ? files[0].name : `${files[0].name} (+${files.length - 1})`
        );
        setFormatDetected(detected);
        setTotalReported(reportedTotal);
        setFilters(INITIAL_FILTER_STATE);
        setPage(1);
        setSelectedAlert(null);
        setNotice(
          totalSkipped > 0
            ? `Loaded ${aggregated.length.toLocaleString()} alerts (${totalSkipped} malformed lines skipped).`
            : null
        );
      }
    },
    []
  );

  // Global drag-and-drop for fast local file inspection
  useEffect(() => {
    const onDragEnter = (e: DragEvent) => {
      if (isUploadOpen) return;
      if (e.dataTransfer?.types.includes('Files')) {
        dragDepthRef.current++;
        setIsGlobalDragging(true);
      }
    };
    const onDragOver = (e: DragEvent) => {
      if (isUploadOpen) return;
      if (e.dataTransfer?.types.includes('Files')) {
        e.preventDefault();
      }
    };
    const onDragLeave = () => {
      if (isUploadOpen) return;
      dragDepthRef.current = Math.max(0, dragDepthRef.current - 1);
      if (dragDepthRef.current === 0) {
        setIsGlobalDragging(false);
      }
    };
    const onDrop = async (e: DragEvent) => {
      if (isUploadOpen) return;
      e.preventDefault();
      dragDepthRef.current = 0;
      setIsGlobalDragging(false);
      const dropped = e.dataTransfer?.files;
      if (!dropped || dropped.length === 0) return;
      try {
        const files = await Promise.all(
          Array.from(dropped).map(async (f) => ({ name: f.name, content: await f.text() }))
        );
        await handleFilesLoaded(files, 'replace');
      } catch (err) {
        setNotice(
          err instanceof Error ? err.message : 'Unable to parse the dropped file.'
        );
      }
    };

    window.addEventListener('dragenter', onDragEnter);
    window.addEventListener('dragover', onDragOver);
    window.addEventListener('dragleave', onDragLeave);
    window.addEventListener('drop', onDrop);
    return () => {
      window.removeEventListener('dragenter', onDragEnter);
      window.removeEventListener('dragover', onDragOver);
      window.removeEventListener('dragleave', onDragLeave);
      window.removeEventListener('drop', onDrop);
    };
  }, [isUploadOpen, handleFilesLoaded]);

  // Derived filtered, sorted, paginated alerts & facets
  const filteredAlerts = useMemo(() => filterAlerts(alerts, filters), [alerts, filters]);

  const sortedAlerts = useMemo(
    () => sortAlerts(filteredAlerts, sortField, sortDirection),
    [filteredAlerts, sortField, sortDirection]
  );

  // Compute sidebar facets from full dataset when nothing is filtered or from filtered view?
  // Computing from filtered alerts keeps counts strictly accurate to the active slice,
  // while preserving selected items via facets of all alerts if needed. Let's compute facets
  // on filteredAlerts for live real-time refinement, and also keep dataset-wide timeSpan.
  const activeFacets = useMemo(() => computeFacets(filteredAlerts), [filteredAlerts]);
  const allFacets = useMemo(() => computeFacets(alerts), [alerts]);

  // Merge facets so any currently-checked option remains visible even if count drops to 0
  const sidebarFacets = useMemo(() => {
    const mergeFacetList = (
      current: typeof activeFacets.agents,
      base: typeof allFacets.agents,
      selected: string[]
    ) => {
      const countMap = new Map(current.map((item) => [item.value, item.count]));
      return base
        .map((item) => ({
          ...item,
          count: countMap.get(item.value) ?? 0,
        }))
        .filter((item) => item.count > 0 || selected.includes(item.value))
        .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
    };

    return {
      severities: activeFacets.severities,
      agents: mergeFacetList(activeFacets.agents, allFacets.agents, filters.agents),
      decoders: mergeFacetList(activeFacets.decoders, allFacets.decoders, filters.decoders),
      groups: mergeFacetList(activeFacets.groups, allFacets.groups, filters.groups),
      scaResults: mergeFacetList(activeFacets.scaResults, allFacets.scaResults, filters.scaResults),
      mitreItems: mergeFacetList(activeFacets.mitreItems, allFacets.mitreItems, filters.mitreItems),
      complianceFrameworks: mergeFacetList(
        activeFacets.complianceFrameworks,
        allFacets.complianceFrameworks,
        filters.complianceFrameworks
      ),
      topRules: activeFacets.topRules,
    };
  }, [activeFacets, allFacets, filters]);

  const timeSpan = useMemo<[number, number] | null>(() => {
    const valid = alerts.filter((a) => a.timestampMs > 0);
    if (valid.length === 0) return null;
    let min = valid[0].timestampMs;
    let max = valid[0].timestampMs;
    for (const a of valid) {
      if (a.timestampMs < min) min = a.timestampMs;
      if (a.timestampMs > max) max = a.timestampMs;
    }
    return [min, max];
  }, [alerts]);

  const isFiltered = useMemo(() => hasActiveFilters(filters), [filters]);

  // Reset page when filter or sort changes
  useEffect(() => {
    setPage(1);
  }, [filters, sortField, sortDirection, pageSize]);

  const paginatedAlerts = useMemo(() => {
    const start = (page - 1) * pageSize;
    return sortedAlerts.slice(start, start + pageSize);
  }, [sortedAlerts, page, pageSize]);

  // KPI metrics
  const kpi = useMemo(() => {
    const mediumPlus =
      activeFacets.severities.medium +
      activeFacets.severities.high +
      activeFacets.severities.critical;
    const highPlus = activeFacets.severities.high + activeFacets.severities.critical;
    const topRule = activeFacets.topRules[0] ?? null;
    return {
      mediumPlus,
      highPlus,
      uniqueAgents: activeFacets.agents.length,
      uniqueDecoders: activeFacets.decoders.length,
      topRule,
    };
  }, [activeFacets]);

  // Handlers
  const handleToggleSeverity = (band: SeverityBand) => {
    setFilters((prev) => ({
      ...prev,
      severities: toggleInArray(prev.severities, band),
    }));
  };

  const handleToggleFacet = (
    key: 'agents' | 'decoders' | 'groups' | 'scaResults' | 'mitreItems' | 'complianceFrameworks',
    value: string
  ) => {
    setFilters((prev) => ({
      ...prev,
      [key]: toggleInArray(prev[key], value),
    }));
  };

  const handleSortChange = (field: SortField) => {
    if (sortField === field) {
      setSortDirection((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDirection(field === 'timestampMs' || field === 'level' ? 'desc' : 'asc');
    }
  };

  const handleQuickFilter = (
    type: 'ruleId' | 'agent' | 'decoder' | 'group' | 'mitre' | 'scaResult' | 'compliance' | 'level',
    value: string,
    switchToEvents = false
  ) => {
    setFilters((prev) => {
      switch (type) {
        case 'ruleId':
          return {
            ...prev,
            ruleIds: prev.ruleIds.includes(value) ? prev.ruleIds : [...prev.ruleIds, value],
          };
        case 'agent':
          return {
            ...prev,
            agents: prev.agents.includes(value) ? prev.agents : [...prev.agents, value],
          };
        case 'decoder':
          return {
            ...prev,
            decoders: prev.decoders.includes(value) ? prev.decoders : [...prev.decoders, value],
          };
        case 'group':
          return {
            ...prev,
            groups: prev.groups.includes(value) ? prev.groups : [...prev.groups, value],
          };
        case 'mitre':
          return {
            ...prev,
            mitreItems: prev.mitreItems.includes(value)
              ? prev.mitreItems
              : [...prev.mitreItems, value],
          };
        case 'scaResult':
          return {
            ...prev,
            scaResults: prev.scaResults.includes(value)
              ? prev.scaResults
              : [...prev.scaResults, value],
          };
        case 'compliance':
          return {
            ...prev,
            complianceFrameworks: prev.complianceFrameworks.includes(value)
              ? prev.complianceFrameworks
              : [...prev.complianceFrameworks, value],
          };
        case 'level': {
          const lvl = Number(value);
          return {
            ...prev,
            minLevel: lvl,
            maxLevel: lvl,
          };
        }
      }
    });
    if (switchToEvents) {
      setActiveTab('events');
    }
  };

  const handleResetFilters = () => {
    setFilters(INITIAL_FILTER_STATE);
  };

  // Active filter chips data (rendered as crisp flat interactive buttons, no pill capsules)
  const activeFilterItems = useMemo(() => {
    const items: Array<{ key: string; label: string; onRemove: () => void }> = [];
    if (filters.search.trim()) {
      items.push({
        key: 'search',
        label: `query: ${filters.search.trim()}`,
        onRemove: () => setFilters((p) => ({ ...p, search: '' })),
      });
    }
    for (const sev of filters.severities) {
      items.push({
        key: `sev-${sev}`,
        label: `severity: ${getSeverityLabel(sev)}`,
        onRemove: () =>
          setFilters((p) => ({ ...p, severities: p.severities.filter((s) => s !== sev) })),
      });
    }
    if (filters.minLevel > 0 || filters.maxLevel < 15) {
      items.push({
        key: 'level-range',
        label: `level: ${filters.minLevel}–${filters.maxLevel}`,
        onRemove: () => setFilters((p) => ({ ...p, minLevel: 0, maxLevel: 15 })),
      });
    }
    for (const r of filters.ruleIds) {
      items.push({
        key: `rule-${r}`,
        label: `rule: ${r}`,
        onRemove: () => setFilters((p) => ({ ...p, ruleIds: p.ruleIds.filter((x) => x !== r) })),
      });
    }
    for (const ag of filters.agents) {
      items.push({
        key: `agent-${ag}`,
        label: `agent: ${ag}`,
        onRemove: () => setFilters((p) => ({ ...p, agents: p.agents.filter((x) => x !== ag) })),
      });
    }
    for (const dec of filters.decoders) {
      items.push({
        key: `dec-${dec}`,
        label: `decoder: ${dec}`,
        onRemove: () =>
          setFilters((p) => ({ ...p, decoders: p.decoders.filter((x) => x !== dec) })),
      });
    }
    for (const grp of filters.groups) {
      items.push({
        key: `grp-${grp}`,
        label: `group: ${grp}`,
        onRemove: () => setFilters((p) => ({ ...p, groups: p.groups.filter((x) => x !== grp) })),
      });
    }
    for (const sca of filters.scaResults) {
      items.push({
        key: `sca-${sca}`,
        label: `sca: ${formatScaResultLabel(sca)}`,
        onRemove: () =>
          setFilters((p) => ({ ...p, scaResults: p.scaResults.filter((x) => x !== sca) })),
      });
    }
    for (const m of filters.mitreItems) {
      items.push({
        key: `mitre-${m}`,
        label: `mitre: ${m}`,
        onRemove: () =>
          setFilters((p) => ({ ...p, mitreItems: p.mitreItems.filter((x) => x !== m) })),
      });
    }
    for (const cf of filters.complianceFrameworks) {
      items.push({
        key: `cf-${cf}`,
        label: `compliance: ${cf}`,
        onRemove: () =>
          setFilters((p) => ({
            ...p,
            complianceFrameworks: p.complianceFrameworks.filter((x) => x !== cf),
          })),
      });
    }
    if (filters.timeRange) {
      items.push({
        key: 'time-range',
        label: `time: ${formatTimeShort(filters.timeRange[0], useUtc)}–${formatTimeShort(filters.timeRange[1], useUtc)}`,
        onRemove: () => setFilters((p) => ({ ...p, timeRange: null })),
      });
    }
    return items;
  }, [filters, useUtc]);

  const scaCount = useMemo(
    () => filteredAlerts.filter((a) => Boolean(a.sca?.check)).length,
    [filteredAlerts]
  );

  return (
    <div className="h-screen flex flex-col bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 overflow-hidden">
      {/* Strict 3-zone Top Header Bar */}
      <header className="h-14 flex-shrink-0 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 px-4 lg:px-6 flex items-center justify-between gap-8">
        {/* Zone 1: Brand / Active dataset context */}
        <div className="flex items-center gap-2.5 min-w-0 whitespace-nowrap">
          <Shield className="w-4 h-4 text-blue-600 dark:text-blue-400 flex-shrink-0" />
          <span className="text-sm font-semibold tracking-tight text-slate-900 dark:text-white">
            Wazuh Lens
          </span>
          <span className="text-slate-300 dark:text-slate-700 hidden sm:inline">/</span>
          <span
            className="text-xs font-mono text-slate-500 dark:text-slate-400 truncate max-w-[160px] md:max-w-[240px] hidden sm:inline"
            title={sourceName}
          >
            {sourceName}
          </span>
        </div>

        {/* Zone 2: Primary view links */}
        <nav
          aria-label="Primary views"
          className="flex items-center gap-6 h-full whitespace-nowrap"
        >
          {(
            [
              { id: 'events', label: 'Events' },
              { id: 'analytics', label: 'Analytics' },
              {
                id: 'sca',
                label: scaCount > 0 ? `SCA Posture (${scaCount})` : 'SCA Posture',
              },
            ] as const
          ).map((nav) => (
            <button
              key={nav.id}
              type="button"
              onClick={() => setActiveTab(nav.id)}
              className={`h-full inline-flex items-center text-xs font-medium border-b-2 transition-colors whitespace-nowrap ${
                activeTab === nav.id
                  ? 'border-blue-600 dark:border-blue-400 text-slate-950 dark:text-white'
                  : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
            >
              {nav.label}
            </button>
          ))}
        </nav>

        {/* Zone 3: Single Primary CTA */}
        <div className="flex items-center flex-shrink-0">
          <button
            type="button"
            onClick={() => setIsUploadOpen(true)}
            className="inline-flex items-center gap-1.5 h-8 px-3.5 rounded-md text-xs font-medium bg-blue-600 hover:bg-blue-700 text-white transition-colors whitespace-nowrap"
          >
            <Upload className="w-3.5 h-3.5" />
            Upload JSON
          </button>
        </div>
      </header>

      {/* Main Split Workspace */}
      <div className="flex-1 flex min-h-0 overflow-hidden">
        {/* Left Facet Sidebar */}
        <SidebarFacets
          facets={sidebarFacets}
          filters={filters}
          totalAlerts={alerts.length}
          filteredCount={filteredAlerts.length}
          formatDetected={formatDetected}
          timeSpan={timeSpan}
          hasActive={isFiltered}
          onToggleSeverity={handleToggleSeverity}
          onLevelChange={(minLevel, maxLevel) =>
            setFilters((prev) => ({ ...prev, minLevel, maxLevel }))
          }
          onToggleFacet={handleToggleFacet}
          onResetFilters={handleResetFilters}
          isOpenMobile={isMobileSidebarOpen}
          onCloseMobile={() => setIsMobileSidebarOpen(false)}
        />

        {/* Primary Main Panel */}
        <main className="flex-1 min-w-0 overflow-y-auto">
          {/* Workspace Toolbar (Search + Utility Controls) */}
          <div className="sticky top-0 z-20 border-b border-slate-200 dark:border-slate-800 bg-white/95 dark:bg-slate-950/95 backdrop-blur-xs px-4 lg:px-6 py-3">
            <div className="flex flex-wrap items-center gap-2.5">
              {/* Mobile Filter Drawer Trigger */}
              <button
                type="button"
                onClick={() => setIsMobileSidebarOpen(true)}
                className="lg:hidden inline-flex items-center gap-1.5 h-9 px-3 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-xs font-medium text-slate-700 dark:text-slate-300"
              >
                <SlidersHorizontal className="w-3.5 h-3.5" />
                Filters
              </button>

              {/* Search Input */}
              <div className="relative flex-1 min-w-[220px]">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  ref={searchInputRef}
                  type="text"
                  value={filters.search}
                  onChange={(e) =>
                    setFilters((prev) => ({ ...prev, search: e.target.value }))
                  }
                  placeholder="Filter alerts... e.g. level>=7 decoder:sca -sca:passed rule:5402"
                  className="w-full h-9 pl-9 pr-16 rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 text-xs font-mono text-slate-900 dark:text-slate-100 placeholder:font-sans placeholder:text-slate-400 focus:outline-none focus:border-blue-500 focus:bg-white dark:focus:bg-slate-900 transition-colors"
                />
                <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1">
                  {filters.search && (
                    <button
                      type="button"
                      onClick={() => setFilters((p) => ({ ...p, search: '' }))}
                      className="p-1 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200"
                      aria-label="Clear search query"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => setShowQueryHelp((s) => !s)}
                    className={`p-1 rounded transition-colors ${
                      showQueryHelp
                        ? 'text-blue-600 dark:text-blue-400'
                        : 'text-slate-400 hover:text-slate-700 dark:hover:text-slate-200'
                    }`}
                    aria-label="Toggle search syntax guide"
                    title="Search query syntax"
                  >
                    <HelpCircle className="w-3.5 h-3.5" />
                  </button>
                </div>

                {/* Query syntax popover */}
                {showQueryHelp && (
                  <div className="absolute left-0 right-0 sm:right-auto sm:w-[460px] top-11 z-30 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 shadow-lg p-3.5 text-xs">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-semibold text-slate-900 dark:text-slate-100">
                        Search Query Syntax
                      </span>
                      <button
                        type="button"
                        onClick={() => setShowQueryHelp(false)}
                        className="text-slate-400 hover:text-slate-700 dark:hover:text-slate-200"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    </div>
                    <p className="text-slate-500 dark:text-slate-400 mb-2.5">
                      Combine free text, exact quotes, negation (<code className="font-mono">-term</code>), and field expressions:
                    </p>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 font-mono text-[11px]">
                      {[
                        ['level>=7', 'Rule level 7 or higher'],
                        ['rule:19007', 'Specific rule ID'],
                        ['decoder:sudo', 'Decoder name'],
                        ['group:dpkg', 'Rule group'],
                        ['sca:failed', 'SCA check result'],
                        ['mitre:T1548', 'MITRE technique/tactic'],
                        ['user:root', 'Source or target user'],
                        ['-sca:passed', 'Exclude passed checks'],
                      ].map(([example, desc]) => (
                        <button
                          key={example}
                          type="button"
                          onClick={() => {
                            setFilters((p) => ({
                              ...p,
                              search: p.search.trim() ? `${p.search.trim()} ${example}` : example,
                            }));
                            setShowQueryHelp(false);
                          }}
                          className="flex items-center justify-between gap-2 px-2 py-1 rounded border border-slate-200 dark:border-slate-800 hover:border-blue-500 text-left transition-colors"
                        >
                          <span className="text-blue-700 dark:text-blue-400">{example}</span>
                          <span className="font-sans text-[10px] text-slate-500 dark:text-slate-400 truncate">
                            {desc}
                          </span>
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Utility controls (UTC toggle, Exports, Theme) */}
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => setUseUtc((u) => !u)}
                  className="inline-flex items-center gap-1.5 h-9 px-2.5 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-xs font-mono text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
                  title="Switch between UTC and local browser time"
                >
                  <Clock className="w-3.5 h-3.5 text-slate-400" />
                  {useUtc ? 'UTC' : 'Local'}
                </button>

                <button
                  type="button"
                  disabled={filteredAlerts.length === 0}
                  onClick={() =>
                    exportAlertsToCsv(
                      sortedAlerts,
                      `wazuh-alerts-filtered-${filteredAlerts.length}.csv`
                    )
                  }
                  className="inline-flex items-center gap-1.5 h-9 px-2.5 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-xs font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-40 transition-colors"
                  title="Export matching alerts as CSV"
                >
                  <Download className="w-3.5 h-3.5 text-slate-400" />
                  <span className="hidden sm:inline">CSV</span>
                </button>

                <button
                  type="button"
                  disabled={filteredAlerts.length === 0}
                  onClick={() =>
                    exportAlertsToJson(
                      sortedAlerts,
                      `wazuh-alerts-filtered-${filteredAlerts.length}.json`
                    )
                  }
                  className="inline-flex items-center gap-1.5 h-9 px-2.5 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-xs font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-40 transition-colors"
                  title="Export matching alerts as JSON"
                >
                  <Download className="w-3.5 h-3.5 text-slate-400" />
                  <span className="hidden sm:inline">JSON</span>
                </button>

                <button
                  type="button"
                  onClick={() => setDarkMode((d) => !d)}
                  className="inline-flex items-center justify-center w-9 h-9 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
                  aria-label={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
                  title={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
                >
                  {darkMode ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Active filters strip */}
            {activeFilterItems.length > 0 && (
              <div className="mt-2.5 pt-2.5 border-t border-slate-100 dark:border-slate-800/80 flex flex-wrap items-center gap-2 text-xs">
                <span className="text-[11px] text-slate-500 dark:text-slate-400">Active:</span>
                {activeFilterItems.map((item) => (
                  <button
                    key={item.key}
                    type="button"
                    onClick={item.onRemove}
                    className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 font-mono text-[11px] text-slate-700 dark:text-slate-300 hover:border-rose-400 hover:text-rose-700 dark:hover:text-rose-400 transition-colors"
                    title="Click to remove filter"
                  >
                    <span>{item.label}</span>
                    <X className="w-3 h-3" />
                  </button>
                ))}
                <button
                  type="button"
                  onClick={handleResetFilters}
                  className="text-xs font-medium text-blue-600 dark:text-blue-400 hover:underline ml-1"
                >
                  Clear all
                </button>
              </div>
            )}
          </div>

          {/* Workspace Body */}
          <div className="p-4 lg:p-6 space-y-4">
            {notice && (
              <div className="flex items-center justify-between gap-3 px-3.5 py-2.5 rounded-md border border-blue-200 dark:border-blue-900/70 bg-blue-50/70 dark:bg-blue-950/40 text-xs text-blue-800 dark:text-blue-200">
                <span>{notice}</span>
                <button
                  type="button"
                  onClick={() => setNotice(null)}
                  className="text-blue-600 dark:text-blue-300 hover:opacity-75"
                  aria-label="Dismiss notice"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            )}

            {loading ? (
              <div className="space-y-4 animate-pulse">
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                  {[0, 1, 2, 3].map((i) => (
                    <div
                      key={i}
                      className="h-20 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/60"
                    />
                  ))}
                </div>
                <div className="h-28 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/60" />
                <div className="h-72 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/60" />
              </div>
            ) : loadError ? (
              <div className="border border-rose-200 dark:border-rose-900/70 rounded-lg bg-white dark:bg-slate-900/60 p-8 text-center">
                <AlertCircle className="w-7 h-7 text-rose-600 dark:text-rose-400 mx-auto mb-2.5" />
                <p className="text-sm font-medium text-slate-900 dark:text-slate-100">
                  {loadError}
                </p>
                <div className="mt-4 flex items-center justify-center gap-3">
                  <button
                    type="button"
                    onClick={() => void loadSampleFile()}
                    className="px-3.5 py-1.5 rounded-md text-xs font-medium bg-blue-600 text-white hover:bg-blue-700"
                  >
                    Retry sample
                  </button>
                  <button
                    type="button"
                    onClick={() => setIsUploadOpen(true)}
                    className="px-3.5 py-1.5 rounded-md text-xs font-medium border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800"
                  >
                    Upload local file
                  </button>
                </div>
              </div>
            ) : (
              <>
                {/* 4-column flat summary KPI strip */}
                <section className="grid grid-cols-2 xl:grid-cols-4 gap-3">
                  <div className="border border-slate-200 dark:border-slate-800 rounded-lg bg-white dark:bg-slate-900/60 px-4 py-3">
                    <div className="text-xs text-slate-500 dark:text-slate-400">
                      Matching Alerts
                    </div>
                    <div className="mt-1 flex items-baseline gap-2">
                      <span className="text-2xl font-semibold font-mono tabular-nums text-slate-900 dark:text-white">
                        {filteredAlerts.length.toLocaleString()}
                      </span>
                      <span className="text-xs font-mono tabular-nums text-slate-400 dark:text-slate-500">
                        / {alerts.length.toLocaleString()} loaded
                      </span>
                    </div>
                    {totalReported && totalReported > alerts.length && (
                      <div className="mt-0.5 text-[11px] text-slate-400 dark:text-slate-500 tabular-nums">
                        {totalReported.toLocaleString()} total reported in export
                      </div>
                    )}
                  </div>

                  <div className="border border-slate-200 dark:border-slate-800 rounded-lg bg-white dark:bg-slate-900/60 px-4 py-3">
                    <div className="text-xs text-slate-500 dark:text-slate-400">
                      Medium+ Alerts (Level ≥ 4)
                    </div>
                    <div className="mt-1 flex items-baseline gap-2">
                      <span className="text-2xl font-semibold font-mono tabular-nums text-amber-700 dark:text-amber-400">
                        {kpi.mediumPlus.toLocaleString()}
                      </span>
                      <span className="text-xs font-mono tabular-nums text-slate-500 dark:text-slate-400">
                        {kpi.highPlus > 0
                          ? `${kpi.highPlus.toLocaleString()} High/Crit`
                          : '0 High/Crit'}
                      </span>
                    </div>
                  </div>

                  <div className="border border-slate-200 dark:border-slate-800 rounded-lg bg-white dark:bg-slate-900/60 px-4 py-3">
                    <div className="text-xs text-slate-500 dark:text-slate-400">
                      Agents & Decoders
                    </div>
                    <div className="mt-1 flex items-baseline gap-2 tabular-nums">
                      <span className="text-2xl font-semibold font-mono text-slate-900 dark:text-white">
                        {kpi.uniqueAgents}
                      </span>
                      <span className="text-xs text-slate-500 dark:text-slate-400">
                        agent{kpi.uniqueAgents === 1 ? '' : 's'} ·{' '}
                        <span className="font-mono text-slate-700 dark:text-slate-300">
                          {kpi.uniqueDecoders}
                        </span>{' '}
                        decoder{kpi.uniqueDecoders === 1 ? '' : 's'}
                      </span>
                    </div>
                  </div>

                  <div className="border border-slate-200 dark:border-slate-800 rounded-lg bg-white dark:bg-slate-900/60 px-4 py-3 min-w-0">
                    <div className="text-xs text-slate-500 dark:text-slate-400">
                      Top Triggered Rule
                    </div>
                    {kpi.topRule ? (
                      <>
                        <div className="mt-1 flex items-baseline gap-2 tabular-nums">
                          <button
                            type="button"
                            onClick={() => handleQuickFilter('ruleId', kpi.topRule!.ruleId, true)}
                            className="text-2xl font-semibold font-mono text-blue-700 dark:text-blue-400 hover:underline"
                          >
                            {kpi.topRule.ruleId}
                          </button>
                          <span className="text-xs font-mono text-slate-500 dark:text-slate-400">
                            {kpi.topRule.count.toLocaleString()} hits
                          </span>
                        </div>
                        <div
                          className="mt-0.5 text-[11px] text-slate-500 dark:text-slate-400 truncate"
                          title={kpi.topRule.description}
                        >
                          {kpi.topRule.description}
                        </div>
                      </>
                    ) : (
                      <div className="mt-1 text-2xl font-semibold font-mono text-slate-400">—</div>
                    )}
                  </div>
                </section>

                {/* Active View Content */}
                {activeTab === 'events' && (
                  <div className="space-y-4">
                    <AlertHistogram
                      alerts={filteredAlerts}
                      activeTimeRange={filters.timeRange}
                      onSelectTimeRange={(range) =>
                        setFilters((prev) => ({ ...prev, timeRange: range }))
                      }
                      useUtc={useUtc}
                    />
                    <AlertTable
                      alerts={paginatedAlerts}
                      totalFiltered={sortedAlerts.length}
                      page={page}
                      pageSize={pageSize}
                      sortField={sortField}
                      sortDirection={sortDirection}
                      selectedAlertUid={selectedAlert?.uid ?? null}
                      useUtc={useUtc}
                      hasActiveFilters={isFiltered}
                      onSortChange={handleSortChange}
                      onSelectAlert={(a) => setSelectedAlert(a)}
                      onPageChange={setPage}
                      onPageSizeChange={setPageSize}
                      onClearFilters={handleResetFilters}
                    />
                  </div>
                )}

                {activeTab === 'analytics' && (
                  <AnalyticsView
                    alerts={filteredAlerts}
                    facets={activeFacets}
                    onFilterAndOpenEvents={(type, value) => handleQuickFilter(type, value, true)}
                  />
                )}

                {activeTab === 'sca' && (
                  <ScaView
                    alerts={filteredAlerts}
                    onInspectAlert={(a) => setSelectedAlert(a)}
                  />
                )}
              </>
            )}
          </div>
        </main>
      </div>

      {/* Alert Detail Inspector Drawer */}
      <AlertInspector
        alert={selectedAlert}
        useUtc={useUtc}
        onClose={() => setSelectedAlert(null)}
        onQuickFilter={(type, value) => handleQuickFilter(type, value, false)}
      />

      {/* Upload / Paste Modal */}
      <UploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onFilesLoaded={handleFilesLoaded}
        onLoadSample={loadSampleFile}
      />

      {/* Global Drag-and-Drop Overlay */}
      {isGlobalDragging && (
        <div className="fixed inset-0 z-50 bg-slate-950/60 backdrop-blur-xs flex items-center justify-center p-6 pointer-events-none">
          <div className="border-2 border-dashed border-blue-400 rounded-xl bg-slate-900/95 px-10 py-8 text-center shadow-2xl">
            <Upload className="w-8 h-8 text-blue-400 mx-auto mb-3" />
            <p className="text-base font-semibold text-white">
              Drop wazuh-alerts.json to load
            </p>
            <p className="mt-1 text-xs text-slate-300">
              Parsed completely locally in your browser
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
