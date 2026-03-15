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
            <linearGradient id="txGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#1eb5ff" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#1eb5ff" stopOpacity={0} />
            </linearGradient>
          </defs>
          <XAxis dataKey="height" hide />
          <YAxis hide domain={[0, 'auto']} />
          <Tooltip
            contentStyle={{
              background: '#161d27',
              border: '1px solid #243040',
              borderRadius: '8px',
              fontSize: '12px',
              color: '#e2e8f0',
              fontFamily: 'var(--font-mono)',
            }}
            labelFormatter={(v) => `Block #${v}`}
            formatter={(value: number, name: string) => {
              if (name === 'txs') return [`${value} txs`, 'Transactions'];
              return [value, name];
            }}
          />
          <Area
            type="monotone"
            dataKey="txs"
            stroke="#1eb5ff"
            strokeWidth={1.5}
            fill="url(#txGradient)"
            dot={false}
            animationDuration={800}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
