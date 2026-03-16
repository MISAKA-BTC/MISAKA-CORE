'use client';

import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import type { BlockProductionPoint } from '@/types/explorer';

interface BlockMiniChartProps {
  data: BlockProductionPoint[];
  height?: number;
}

export function BlockMiniChart({ data, height = 160 }: BlockMiniChartProps) {
  const chartData = data.map((d) => ({
    height: d.height,
    txs: d.txCount,
    time: d.blockTime.toFixed(1),
  }));

  return (
    <div style={{ width: '100%', height }}>
      <ResponsiveContainer>
        <AreaChart data={chartData} margin={{ top: 4, right: 4, left: 4, bottom: 4 }}>
          <defs>
            <linearGradient id="txGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#ffffff" stopOpacity={0.08} />
              <stop offset="95%" stopColor="#ffffff" stopOpacity={0} />
            </linearGradient>
          </defs>
          <XAxis dataKey="height" hide />
          <YAxis hide domain={[0, 'auto']} />
          <Tooltip
            contentStyle={{
              background: '#111111',
              border: '1px solid #1a1a1a',
              borderRadius: '0',
              fontSize: '11px',
              color: '#999',
              fontFamily: '"JetBrains Mono", monospace',
              letterSpacing: '0.05em',
            }}
            labelFormatter={(v) => `Block #${v}`}
            formatter={(value: number, name: string) => {
              if (name === 'txs') return [`${value}`, 'TXS'];
              return [value, name];
            }}
          />
          <Area
            type="monotone"
            dataKey="txs"
            stroke="#666666"
            strokeWidth={1}
            fill="url(#txGrad)"
            dot={false}
            animationDuration={600}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
