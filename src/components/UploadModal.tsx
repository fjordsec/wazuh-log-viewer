import React, { useRef, useState } from 'react';
import { AlertCircle, FileJson, Upload, X } from 'lucide-react';

interface UploadModalProps {
  isOpen: boolean;
  onClose: () => void;
  onFilesLoaded: (files: Array<{ name: string; content: string }>, mode: 'replace' | 'append') => Promise<void> | void;
  onLoadSample: () => Promise<void> | void;
}

type ModalTab = 'file' | 'paste';

export function UploadModal({
  isOpen,
  onClose,
  onFilesLoaded,
  onLoadSample,
}: UploadModalProps) {
  const [tab, setTab] = useState<ModalTab>('file');
  const [mode, setMode] = useState<'replace' | 'append'>('replace');
  const [pastedText, setPastedText] = useState('');
  const [isDragging, setIsDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  const processFileList = async (fileList: FileList | null) => {
    if (!fileList || fileList.length === 0) return;
    setError(null);
    setBusy(true);
    try {
      const files = await Promise.all(
        Array.from(fileList).map(async (file) => ({
          name: file.name,
          content: await file.text(),
        }))
      );
      await onFilesLoaded(files, mode);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to parse selected file.');
    } finally {
      setBusy(false);
    }
  };

  const handlePasteSubmit = async () => {
    if (!pastedText.trim()) {
      setError('Paste a Wazuh JSON export or NDJSON lines first.');
      return;
    }
    setError(null);
    setBusy(true);
    try {
      await onFilesLoaded([{ name: 'pasted-alerts.json', content: pastedText }], mode);
      setPastedText('');
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to parse pasted JSON.');
    } finally {
      setBusy(false);
    }
  };

  const handleSampleClick = async () => {
    setError(null);
    setBusy(true);
    try {
      await onLoadSample();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load sample alerts.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        className="fixed inset-0 bg-slate-950/50 backdrop-blur-[1px]"
        onClick={onClose}
      />

      <div
        role="dialog"
        aria-label="Upload Wazuh alerts JSON"
        className="relative z-10 w-full max-w-lg rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 shadow-2xl overflow-hidden"
      >
        {/* Header */}
        <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              Load Wazuh Alerts File
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Processed locally in your browser — files never leave your machine.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-md text-slate-500 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800"
            aria-label="Close upload dialog"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Mode & Source Tabs */}
        <div className="px-5 pt-4 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-4 border-b border-transparent">
            <button
              type="button"
              onClick={() => {
                setTab('file');
                setError(null);
              }}
              className={`pb-1.5 text-xs font-medium border-b-2 transition-colors ${
                tab === 'file'
                  ? 'border-blue-600 dark:border-blue-400 text-slate-900 dark:text-white'
                  : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
            >
              Upload File(s)
            </button>
            <button
              type="button"
              onClick={() => {
                setTab('paste');
                setError(null);
              }}
              className={`pb-1.5 text-xs font-medium border-b-2 transition-colors ${
                tab === 'paste'
                  ? 'border-blue-600 dark:border-blue-400 text-slate-900 dark:text-white'
                  : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
            >
              Paste JSON / NDJSON
            </button>
          </div>

          <div className="flex items-center gap-1 text-xs">
            <button
              type="button"
              onClick={() => setMode('replace')}
              className={`px-2.5 py-1 rounded-md font-medium transition-colors ${
                mode === 'replace'
                  ? 'bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-950'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
              }`}
            >
              Replace
            </button>
            <button
              type="button"
              onClick={() => setMode('append')}
              className={`px-2.5 py-1 rounded-md font-medium transition-colors ${
                mode === 'append'
                  ? 'bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-950'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
              }`}
            >
              Append
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="p-5 space-y-4">
          {tab === 'file' ? (
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setIsDragging(true);
              }}
              onDragLeave={() => setIsDragging(false)}
              onDrop={(e) => {
                e.preventDefault();
                setIsDragging(false);
                void processFileList(e.dataTransfer.files);
              }}
              onClick={() => fileInputRef.current?.click()}
              className={`cursor-pointer rounded-lg border-2 border-dashed p-8 text-center transition-colors ${
                isDragging
                  ? 'border-blue-500 bg-blue-50/70 dark:bg-blue-950/40'
                  : 'border-slate-300 dark:border-slate-700 hover:border-blue-500 dark:hover:border-blue-400 bg-slate-50/60 dark:bg-slate-900/40'
              }`}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".json,.jsonl,.ndjson,.log,.txt,application/json"
                multiple
                onChange={(e) => void processFileList(e.target.files)}
                className="hidden"
              />
              <Upload className="w-7 h-7 text-slate-400 dark:text-slate-500 mx-auto mb-2.5" />
              <p className="text-sm font-medium text-slate-800 dark:text-slate-200">
                {busy ? 'Parsing alerts...' : 'Drop wazuh-alerts.json here, or click to browse'}
              </p>
              <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                Supports OpenSearch/Elasticsearch exports, JSON arrays, and NDJSON (alerts.json)
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              <textarea
                value={pastedText}
                onChange={(e) => setPastedText(e.target.value)}
                rows={8}
                placeholder='Paste OpenSearch export JSON, a JSON array, or newline-delimited alerts.json lines...'
                className="w-full p-3 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 font-mono text-xs text-slate-800 dark:text-slate-200 placeholder:text-slate-400 focus:outline-none focus:border-blue-500"
              />
              <div className="flex justify-end">
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => void handlePasteSubmit()}
                  className="px-3.5 py-1.5 rounded-md text-xs font-medium bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 transition-colors"
                >
                  {busy ? 'Parsing...' : mode === 'replace' ? 'Load Alerts' : 'Append Alerts'}
                </button>
              </div>
            </div>
          )}

          {error && (
            <div className="flex items-start gap-2 p-3 rounded-md border border-rose-200 dark:border-rose-900/70 bg-rose-50 dark:bg-rose-950/40 text-xs text-rose-700 dark:text-rose-300">
              <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {/* Footer helper */}
          <div className="pt-3 border-t border-slate-200 dark:border-slate-800 flex flex-wrap items-center justify-between gap-2 text-xs">
            <span className="text-slate-500 dark:text-slate-400">
              Want to reset to the attached reference dataset?
            </span>
            <button
              type="button"
              disabled={busy}
              onClick={() => void handleSampleClick()}
              className="inline-flex items-center gap-1.5 font-medium text-blue-600 dark:text-blue-400 hover:underline disabled:opacity-50"
            >
              <FileJson className="w-3.5 h-3.5" />
              Load sample wazuh-alerts.json
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
