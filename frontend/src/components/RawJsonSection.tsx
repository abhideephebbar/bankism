import React, { useRef, useState } from 'react';

interface RawJsonSectionProps {
  /** The exact API response object to display and copy. Never fabricated. */
  data: unknown;
  /** Distinguishes evaluation vs process JSON so the two are never confused. */
  label: string;
}

type CopyState = 'idle' | 'copied' | 'error';

/**
 * Explicit "Raw JSON" disclosure: formatted, plain-text rendering of the
 * actual backend response, with an exact-copy button. Collapsed by default.
 */
export const RawJsonSection: React.FC<RawJsonSectionProps> = ({ data, label }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [copyState, setCopyState] = useState<CopyState>('idle');
  const resetTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const jsonText = JSON.stringify(data, null, 2);

  const handleCopy = async () => {
    if (resetTimerRef.current) clearTimeout(resetTimerRef.current);
    try {
      await navigator.clipboard.writeText(jsonText);
      setCopyState('copied');
    } catch {
      setCopyState('error');
    }
    resetTimerRef.current = setTimeout(() => setCopyState('idle'), 2000);
  };

  return (
    <div className="raw-json-section" data-raw-json={label}>
      <div className="raw-json-header">
        <button
          type="button"
          className="details-toggle"
          onClick={() => setIsOpen(!isOpen)}
          aria-expanded={isOpen}
        >
          <span className="chevron" aria-hidden="true">
            ▶
          </span>
          Raw JSON
        </button>
        {isOpen && (
          <button
            type="button"
            className="btn btn-secondary raw-json-copy"
            onClick={handleCopy}
            style={{ fontSize: 11, padding: '3px 10px' }}
          >
            {copyState === 'copied'
              ? 'Copied'
              : copyState === 'error'
              ? 'Copy failed — try again'
              : 'Copy JSON'}
          </button>
        )}
      </div>

      {isOpen && (
        <pre className="details-json raw-json-pre" aria-label={`Raw JSON, ${label}`}>
          {jsonText}
        </pre>
      )}
    </div>
  );
};
