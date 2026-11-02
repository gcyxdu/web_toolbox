import { useMemo, useState } from 'react';
import { ListBullets, Pulse } from '@phosphor-icons/react';
import { SegmentedControl } from '@radix-ui/themes';
import { percent } from '../../config';
import Chart from './LazyChart';
import { METRIC_COLORS } from './chartColors';
import type { Projection, RunEvent } from '../../types';

const eventLabels: Record<string, string> = {
  run_created: '实验已创建',
  run_started: '训练进程启动',
  data_prepared: '数据划分完成',
  engine_ready: '训练环境就绪',
  round_started: '开始本轮训练',
  aggregation_started: '服务端开始聚合',
  aggregation_completed: '聚合完成',
  round_completed: '全局评估完成',
  run_completed: '实验完成',
  run_cancelled: '实验已取消',
  run_failed: '实验运行失败',
  cancel_requested: '正在停止训练',
};

export default function Metrics({
  projection,
  events,
}: {
  projection: Projection;
  events: RunEvent[];
}) {
  const [tab, setTab] = useState('metrics');
  const [secondary, setSecondary] = useState('loss');
  const latest = projection.metrics.at(-1);
  const clean = useMemo(
    () => [{ name: '全局准确率', metrics: projection.metrics, color: METRIC_COLORS.accuracy }],
    [projection.metrics],
  );
  const auxiliary = useMemo(
    () => [
      {
        name: secondary === 'asr' ? '后门成功率' : '测试损失',
        metrics: projection.metrics,
        color: secondary === 'asr' ? METRIC_COLORS.asr : METRIC_COLORS.loss,
      },
    ],
    [projection.metrics, secondary],
  );
  const notable = events.filter(
    (event) => event.type !== 'client_started' && event.type !== 'client_completed',
  );
  return (
    <section className="metrics-panel">
      <div className="panel-toolbar">
        <div className="panel-title">
          <Pulse size={17} />
          <strong>实验观测</strong>
          <span className="subtle-label">实时评估</span>
        </div>
        <SegmentedControl.Root size="1" value={tab} onValueChange={setTab}>
          <SegmentedControl.Item value="metrics">指标曲线</SegmentedControl.Item>
          <SegmentedControl.Item value="events">事件日志</SegmentedControl.Item>
        </SegmentedControl.Root>
      </div>
      {tab === 'metrics' ? (
        <div className="metric-charts">
          <div className="chart-panel">
            <div className="chart-heading">
              <span>全局测试准确率</span>
              <strong className="mono">{percent(latest?.accuracy)}</strong>
            </div>
            <Chart series={clean} label="测试准确率" />
          </div>
          <div className="chart-panel">
            <div className="chart-heading">
              <select
                aria-label="次要指标"
                value={secondary}
                onChange={(e) => setSecondary(e.target.value)}
              >
                <option value="loss">测试损失</option>
                <option value="asr">后门成功率 ASR</option>
              </select>
              <strong className="mono">
                {secondary === 'loss'
                  ? (latest?.loss?.toFixed(4) ?? '待运行')
                  : percent(latest?.asr)}
              </strong>
            </div>
            {secondary === 'asr' && latest && latest.asr === undefined ? (
              <div className="chart-empty">
                <span>当前场景未定义后门 ASR</span>
                <small>使用后门攻击场景可观察此指标</small>
              </div>
            ) : (
              <Chart
                series={auxiliary}
                kind={secondary as 'loss' | 'asr'}
                label={secondary === 'asr' ? '后门成功率' : '测试损失'}
              />
            )}
          </div>
        </div>
      ) : (
        <div className="event-log">
          {notable.length ? (
            notable
              .slice(-60)
              .reverse()
              .map((event) => (
                <div className="event-row" key={event.seq}>
                  <span className="mono">
                    {event.timestamp
                      ? new Date(event.timestamp).toLocaleTimeString('zh-CN', { hour12: false })
                      : ''}
                  </span>
                  <span>{event.payload.round ? `第 ${event.payload.round} 轮` : '系统'}</span>
                  <strong>{eventLabels[event.type] ?? event.type}</strong>
                  <span>
                    {event.type === 'round_completed'
                      ? `准确率 ${percent(event.payload.accuracy)}`
                      : event.payload.layersift
                        ? `LayerSift · 入选 ${event.payload.layersift.selected_count}/${event.payload.layersift.participant_count} · ${event.payload.layersift.projection_dimension} 维`
                        : String(event.payload.error ?? '')}
                  </span>
                </div>
              ))
          ) : (
            <div className="chart-empty">
              <ListBullets size={25} />
              <span>运行后记录训练事件</span>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
