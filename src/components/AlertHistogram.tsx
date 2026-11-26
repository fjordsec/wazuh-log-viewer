import React, { useMemo, useState } from 'react';
import { RotateCcw } from 'lucide-react';
import { NormalizedAlert, SeverityBand } from '../types/wazuh';
import {
  formatDateShort,
  formatTimeShort,
  severityBarFill,
  severityDotClass,
} from '../utils/formatters';

interface AlertHistogramProps {
  alerts: NormalizedAlert[];
  activeTimeRange: [number, number] | null;
  onSelectTimeRange: (range: [number, number] | null) => void;
  useUtc: boolean;
}

interface Bucket {
  startMs: number;
  endMs: number;
  total: number;
  counts: Record<SeverityBand, number>;
}

const BANDS: SeverityBand[] = ['low', 'medium', 'high', 'critical'];

export function AlertHistogram({
  alerts,
  activeTimeRange,
  onSelectTimeRange,
  useUtc,
}: AlertHistogramProps) {
  const [hoveredIdx, setHoveredIdx] = useState<number | null>(null);

  const { buckets, maxTotal, minMs, maxMs } = useMemo(() => {
    const valid = alerts.filter((a) => a.timestampMs > 0);
    if (valid.length === 0) {
      return { buckets: [] as Bucket[], maxTotal: 0, minMs: 0, maxMs: 0 };
    }

    let min = valid[0].timestampMs;
    let max = valid[0].timestampMs;
    for (const a of valid) {
      if (a.timestampMs < min) min = a.timestampMs;
      if (a.timestampMs > max) max = a.timestampMs;
    }

    const span = max - min;
    const bucketCount = span === 0 ? 1 : Math.min(36, Math.max(12, Math.ceil(Math.sqrt(valid.length) * 2)));
    const step = span === 0 ? 1000 : Math.max(1, Math.ceil((span + 1) / bucketCount));

    const result: Bucket[] = Array.from({ length: bucketCount }, (_, i) => ({
      startMs: min + i * step,
      endMs: min + (i + 1) * step,
      total: 0,
      counts: { critical: 0, high: 0, medium: 0, low: 0 },
    }));

    for (const a of valid) {
      const idx =
        span === 0
          ? 0
          : Math.min(bucketCount - 1, Math.floor((a.timestampMs - min) / step));
      const b = result[idx];
      b.total++;
      b.counts[a.severity]++;
    }

    let maxT = 0;
    for (const b of result) {
      if (b.total > maxT) maxT = b.total;
    }

    return { buckets: result, maxTotal: maxT, minMs: min, maxMs: max };
  }, [alerts]);

  if (buckets.length === 0) {
    return null;
  }

  const hoveredBucket = hoveredIdx !== null ? buckets[hoveredIdx] : null;
  const chartHeight = 76;

  return (
    <section className="border border-slate-200 dark:border-slate-800 rounded-lg bg-white dark:bg-slate-900/60 px-4 py-3">
      <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
        <div className="flex items-center gap-3 min-w-0">
          <h2 className="text-xs font-semibold text-slate-800 dark:text-slate-200">
            Alert Volume Timeline
          </h2>
          <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400 tabular-nums truncate">
            {hoveredBucket
              ? `${formatTimeShort(hoveredBucket.startMs, useUtc)} – ${formatTimeShort(hoveredBucket.endMs, useUtc)} · ${hoveredBucket.total} alert${hoveredBucket.total === 1 ? '' : 's'}`
              : `${formatDateShort(minMs, useUtc)} ${formatTimeShort(minMs, useUtc)} — ${formatTimeShort(maxMs, useUtc)}${useUtc ? ' UTC' : ''}`}
          </span>
        </div>

        <div className="flex items-center gap-3 text-[11px] text-slate-500 dark:text-slate-400">
          <div className="hidden sm:flex items-center gap-3">
            {(['critical', 'high', 'medium', 'low'] as SeverityBand[]).map((band) => (
              <span key={band} className="inline-flex items-center gap-1 capitalize">
                <span className={`w-2 h-2 rounded-xs ${severityDotClass(band)}`} />
                {band}
              </span>
            ))}
          </div>
          {activeTimeRange && (
            <button
              type="button"
              onClick={() => onSelectTimeRange(null)}
              className="inline-flex items-center gap-1 text-xs font-medium text-blue-600 dark:text-blue-400 hover:underline"
            >
              <RotateCcw className="w-3 h-3" />
              Reset window
            </button>
          )}
        </div>
      </div>

      <div className="relative">
        <svg
          viewBox={`0 0 ${buckets.length * 24} ${chartHeight}`}
          className="w-full h-[76px] overflow-visible select-none"
          preserveAspectRatio="none"
          role="img"
          aria-label="Alert count histogram over time"
          onMouseLeave={() => setHoveredIdx(null)}
        >
          {/* Baseline hairline */}
          <line
            x1={0}
            y1={chartHeight - 1}
            x2={buckets.length * 24}
            y2={chartHeight - 1}
            className="stroke-slate-200 dark:stroke-slate-800"
            strokeWidth={1}
          />

          {buckets.map((bucket, idx) => {
            const x = idx * 24 + 2;
            const width = 20;
            const scale = maxTotal > 0 ? (chartHeight - 6) / maxTotal : 0;
            let currentY = chartHeight - 1;
            const isHovered = hoveredIdx === idx;
            const isSelected =
              activeTimeRange !== null &&
              bucket.startMs >= activeTimeRange[0] &&
              bucket.endMs <= activeTimeRange[1] + 1;

            return (
              <g
                key={bucket.startMs}
                className="cursor-pointer"
                onMouseEnter={() => setHoveredIdx(idx)}
                onClick={() => {
                  if (bucket.total === 0) return;
                  if (isSelected) {
                    onSelectTimeRange(null);
                  } else {
                    onSelectTimeRange([bucket.startMs, bucket.endMs]);
                  }
                }}
              >
                {/* Invisible hit target for easy clicking & hovering */}
                <rect
                  x={idx * 24}
                  y={0}
                  width={24}
                  height={chartHeight}
                  fill={isHovered ? 'currentColor' : 'transparent'}
                  className={isHovered ? 'text-slate-900/5 dark:text-white/5' : ''}
                />
                {BANDS.map((band) => {
                  const count = bucket.counts[band];
                  if (count === 0) return null;
                  const h = Math.max(2, count * scale);
                  currentY -= h;
                  return (
                    <rect
                      key={band}
                      x={x}
                      y={currentY}
                      width={width}
                      height={h}
                      rx={1}
                      fill={severityBarFill(band)}
                      opacity={hoveredIdx !== null && !isHovered ? 0.55 : 0.92}
                    />
                  );
                })}
              </g>
            );
          })}
        </svg>

        <div className="mt-1 flex items-center justify-between text-[10px] font-mono text-slate-400 dark:text-slate-500 tabular-nums">
          <span>{formatTimeShort(minMs, useUtc)}</span>
          <span className="hidden sm:inline">Click any bar to narrow time window</span>
          <span>{formatTimeShort(maxMs, useUtc)}</span>
        </div>
      </div>
    </section>
  );
}
