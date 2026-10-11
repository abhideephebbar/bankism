import React, { useEffect, useState } from 'react';
import { Decision, RiskLevel, ThreatCategory } from '../types/firewall';

export type CoreState =
  | 'idle'
  | 'evaluating'
  | 'approved'
  | 'threat_neutralized'
  | 'stale'
  | 'processing';

interface AICoreRadarProps {
  state: CoreState;
  decision?: Decision | null;
  riskLevel?: RiskLevel | null;
  threatCategory?: ThreatCategory | null;
  size?: number;
  className?: string;
  isStale?: boolean;
}

export const AICoreRadar: React.FC<AICoreRadarProps> = ({
  state,
  size = 280,
  className = '',
  isStale = false,
}) => {
  const [isTabVisible, setIsTabVisible] = useState(!document.hidden);
  const [threatSequenceKey, setThreatSequenceKey] = useState(0);

  useEffect(() => {
    const handleVisibility = () => setIsTabVisible(!document.hidden);
    document.addEventListener('visibilitychange', handleVisibility);
    return () => document.removeEventListener('visibilitychange', handleVisibility);
  }, []);

  // Replay the neutralization sequence each time a threat verdict arrives.
  useEffect(() => {
    if (state === 'threat_neutralized') {
      setThreatSequenceKey((k) => k + 1);
    }
  }, [state]);

  // Color scheme based on state
  let primaryColor = '#00f2fe'; // cyan default
  let secondaryColor = '#2575fc';
  let glowColor = 'rgba(0, 242, 254, 0.4)';

  if (isStale || state === 'stale') {
    primaryColor = '#5e738f';
    secondaryColor = '#3a4a5e';
    glowColor = 'rgba(94, 115, 143, 0.2)';
  } else if (state === 'approved') {
    primaryColor = '#00ffa3';
    secondaryColor = '#00b478';
    glowColor = 'rgba(0, 255, 163, 0.45)';
  } else if (state === 'threat_neutralized') {
    primaryColor = '#ff2a5f';
    secondaryColor = '#b30035';
    glowColor = 'rgba(255, 42, 95, 0.6)';
  } else if (state === 'processing') {
    primaryColor = '#00e5ff';
    secondaryColor = '#0077ff';
    glowColor = 'rgba(0, 229, 255, 0.6)';
  }

  const paused = !isTabVisible;

  const rotationSpeed = paused
    ? '0s'
    : state === 'evaluating'
    ? '5s'
    : state === 'processing'
    ? '6s'
    : '18s';

  const counterRotationSpeed = paused ? '0s' : state === 'evaluating' ? '7s' : '26s';

  return (
    <div
      className={`bankism-core-wrapper ${className}`}
      style={{
        width: size,
        height: size,
        position: 'relative',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        margin: '0 auto',
      }}
      role="img"
      aria-label={`Bankism security core status: ${state}${
        isStale ? ' (stale verdict)' : ''
      }`}
    >
      <svg
        width={size}
        height={size}
        viewBox="0 0 300 300"
        style={{
          overflow: 'visible',
          filter: `drop-shadow(0 0 18px ${glowColor})`,
          transition: 'filter 600ms cubic-bezier(0.22, 1, 0.36, 1)',
        }}
      >
        <defs>
          <radialGradient id="coreCenterGradient" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor={primaryColor} stopOpacity="0.8" />
            <stop offset="60%" stopColor={secondaryColor} stopOpacity="0.3" />
            <stop offset="100%" stopColor="#04060a" stopOpacity="0" />
          </radialGradient>

          <linearGradient id="sweepGradient" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor={primaryColor} stopOpacity="0.35" />
            <stop offset="100%" stopColor={primaryColor} stopOpacity="0" />
          </linearGradient>
        </defs>

        {/* Quiet outer boundary ring */}
        <circle
          cx="150"
          cy="150"
          r="140"
          fill="none"
          stroke={primaryColor}
          strokeWidth="1"
          strokeOpacity="0.18"
        />

        {/* Central luminous core: calm breathing while idle */}
        <circle
          cx="150"
          cy="150"
          r={state === 'evaluating' ? '46' : '38'}
          fill="url(#coreCenterGradient)"
          style={
            threatSequenceKey > 0 && state === 'threat_neutralized'
              ? {
                  transformOrigin: '150px 150px',
                  animation: `threatSequence 900ms cubic-bezier(0.22, 1, 0.36, 1) both`,
                }
              : {
                  transformOrigin: '150px 150px',
                  animation: paused ? undefined : 'coreBreathe 4.5s ease-in-out infinite',
                  transition: 'r 400ms cubic-bezier(0.22, 1, 0.36, 1)',
                }
          }
        />
        <circle cx="150" cy="150" r="7" fill={primaryColor} opacity="0.9" />

        {/* Expanding scan wave — only during the neutralization sequence */}
        {state === 'threat_neutralized' && threatSequenceKey > 0 && (
          <g
            key={threatSequenceKey}
            style={{
              transformOrigin: '150px 150px',
              animation: 'coreScanOut 900ms cubic-bezier(0.22, 1, 0.36, 1) both',
            }}
          >
            <circle
              cx="150"
              cy="150"
              r="52"
              fill="none"
              stroke={primaryColor}
              strokeWidth="2"
              strokeOpacity="0.8"
            />
          </g>
        )}

        {/* Primary orbital ring */}
        <g
          style={{
            transformOrigin: '150px 150px',
            animation: `radarSweep ${rotationSpeed} linear infinite`,
          }}
        >
          <circle
            cx="150"
            cy="150"
            r={state === 'evaluating' ? '108' : '118'}
            fill="none"
            stroke={primaryColor}
            strokeWidth="1.4"
            strokeDasharray="120 40 24 40"
            strokeOpacity="0.6"
            strokeLinecap="round"
            style={{ transition: 'r 400ms cubic-bezier(0.22, 1, 0.36, 1)' }}
          />
          <circle cx="150" cy="32" r="3" fill={primaryColor} opacity="0.9" />
        </g>

        {/* Counter-rotating inner ring */}
        <g
          style={{
            transformOrigin: '150px 150px',
            animation: `radarSweep ${counterRotationSpeed} linear infinite reverse`,
          }}
        >
          <circle
            cx="150"
            cy="150"
            r={state === 'evaluating' ? '76' : '86'}
            fill="none"
            stroke={secondaryColor}
            strokeWidth="1.1"
            strokeDasharray="26 18 70 20"
            strokeOpacity="0.5"
            strokeLinecap="round"
            style={{ transition: 'r 400ms cubic-bezier(0.22, 1, 0.36, 1)' }}
          />
          <circle cx="150" cy="64" r="2.2" fill={primaryColor} opacity="0.7" />
        </g>

        {/* Restrained scanner sweep */}
        {state !== 'stale' && (
          <g
            style={{
              transformOrigin: '150px 150px',
              animation: `radarSweep ${
                paused ? '0s' : state === 'evaluating' ? '2.4s' : '7s'
              } linear infinite`,
            }}
          >
            <path
              d="M 150 150 L 150 22 A 128 128 0 0 1 240 59 Z"
              fill="url(#sweepGradient)"
              opacity={state === 'evaluating' ? '0.55' : '0.22'}
            />
          </g>
        )}
      </svg>
    </div>
  );
};
