import { useEffect, useRef } from 'react';
import * as echarts from 'echarts/core';
import { LineChart } from 'echarts/charts';
import { GridComponent, TooltipComponent, LegendComponent } from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';
import { ChartLine } from '@phosphor-icons/react';
import type { MetricPoint } from '../../types';
import { distinctChartColors } from './chartColors';

echarts.use([LineChart, GridComponent, TooltipComponent, LegendComponent, CanvasRenderer]);
export interface ChartSeries {
  name: string;
  metrics: MetricPoint[];
  color: string;
  key?: 'accuracy' | 'loss' | 'asr';
}
export default function Chart({
  series,
  kind = 'accuracy',
  label,
}: {
  series: ChartSeries[];
  kind?: 'accuracy' | 'loss' | 'asr';
  label: string;
}) {
  const element = useRef<HTMLDivElement>(null);
  const instance = useRef<echarts.ECharts | null>(null);
  const hasData = series.some((item) => item.metrics.length > 0);
  useEffect(() => {
    if (!element.current || !hasData) return;
    const chart = echarts.init(element.current, undefined, { renderer: 'canvas' });
    instance.current = chart;
    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(element.current);
    return () => {
      observer.disconnect();
      chart.dispose();
      instance.current = null;
    };
  }, [hasData]);
  useEffect(() => {
    if (!instance.current) return;
    const isLoss = kind === 'loss';
    const colors = distinctChartColors(series.map((item) => item.color));
    instance.current.setOption(
      {
        animation: false,
        textStyle: {
          fontFamily: 'Microsoft YaHei UI, Microsoft YaHei, sans-serif',
          fontSize: 13,
          color: '#798690',
        },
        grid: { left: 48, right: 20, top: 18, bottom: series.length > 1 ? 64 : 44 },
        tooltip: {
          trigger: 'axis',
          backgroundColor: '#fff',
          borderColor: '#e0e6ea',
          textStyle: { fontSize: 14, color: '#35414a' },
          axisPointer: { type: 'line', snap: true },
          confine: true,
          order: 'valueDesc',
          valueFormatter: (value: number) =>
            isLoss ? value.toFixed(4) : `${(value * 100).toFixed(1)}%`,
        },
        legend: {
          show: series.length > 1,
          bottom: 0,
          icon: 'roundRect',
          itemWidth: 12,
          itemHeight: 3,
          textStyle: { color: '#64717b', fontSize: 12 },
        },
        xAxis: {
          type: 'value',
          min: 1,
          max: Math.max(2, ...series.flatMap((item) => item.metrics.map((metric) => metric.round))),
          minInterval: 1,
          axisPointer: { label: { formatter: ({ value }: { value: number | string }) => `第 ${Number(value)} 轮` } },
          name: '通信轮次',
          nameLocation: 'middle',
          nameGap: 28,
          axisLine: { lineStyle: { color: '#dfe6ea' } },
          axisTick: { show: false },
          splitLine: { show: false },
          axisLabel: { margin: 10 },
        },
        yAxis: {
          type: 'value',
          min: 0,
          max: isLoss ? undefined : 1,
          interval: isLoss ? undefined : 0.25,
          splitNumber: 4,
          axisLabel: {
            formatter: (value: number) =>
              isLoss ? value.toFixed(1) : `${Math.round(value * 100)}%`,
          },
          splitLine: { lineStyle: { color: '#edf1f3', type: 'dashed' } },
        },
        color: colors,
        series: series.map((item, index) => ({
          name: item.name,
          type: 'line',
          smooth: false,
          showSymbol: true,
          symbol: 'circle',
          symbolSize: item.metrics.length > 100 ? 3 : 4.5,
          data: item.metrics.map((metric) => [metric.round, metric[item.key ?? kind] ?? null]),
          connectNulls: false,
          lineStyle: { width: 2.5, color: colors[index] },
          itemStyle: { color: colors[index] },
        })),
      },
      true,
    );
  }, [series, kind, hasData]);
  return hasData ? (
    <div key="plot" ref={element} className="line-chart" role="img" aria-label={label} />
  ) : (
    <div key="empty" className="chart-empty">
      <ChartLine size={29} weight="light" />
      <span>训练开始后显示{label}</span>
    </div>
  );
}
