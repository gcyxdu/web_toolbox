import { Server } from '../icons/EvaIcons';
import ClientDevice from '../icons/ClientDevice';
import { modelNames } from '../../config';
import { memo } from 'react';
import { Handle, Position, type Node, type NodeProps } from '@xyflow/react';
import { Check, Minus, CircleNotch } from '@phosphor-icons/react';

export type TopologyNodeData = Record<string, unknown> & {
  label: string;
  malicious?: boolean;
  showRoles?: boolean;
  samples?: number;
  state?: string;
  included?: boolean;
  side?: 'left' | 'right';
  phase?: string;
  algorithm?: string;
  model?: keyof typeof modelNames;
  round?: number;
  rounds?: number;
};
export type TopologyNode = Node<TopologyNodeData>;

export const ClientNode = memo(function ClientNode({ data, selected }: NodeProps<TopologyNode>) {
  const attacking = data.malicious && data.showRoles;
  return (
    <div
      className={`client-node ${selected ? 'is-selected' : ''} ${attacking ? 'is-attacker' : ''} ${data.state === 'training' ? 'is-training' : ''}`}
    >
      <Handle type="source" position={data.side === 'left' ? Position.Right : Position.Left} />
      <div className="client-node-top">
        <span className="node-icon">
          <ClientDevice malicious={!!attacking} size={33} />
        </span>
        <strong>{data.label}</strong>
        {data.state === 'aggregated' ? (
          data.included === false ? (
            <Minus size={14} className="filtered-icon" aria-label="未入选" />
          ) : (
            <Check
              size={12}
              className="done-icon"
              aria-label={data.included ? '入选聚合' : '聚合完成'}
            />
          )
        ) : null}
      </div>
      <div className="client-node-bottom">
        <span className={`node-role ${attacking ? 'attacker' : 'normal'}`}>
          {attacking ? '恶意' : data.showRoles ? '良性' : '客户端'}
        </span>
        {data.state === 'training' ? (
          <>
            <CircleNotch size={10} className="spin" />
            本地训练
          </>
        ) : data.state === 'uploaded' ? (
          '更新已上传'
        ) : data.included !== undefined ? (
          <span className={`node-selection ${data.included ? 'included' : 'excluded'}`}>
            {data.included ? '入选聚合' : '未入选'}
          </span>
        ) : (
          <>
            <span className="mono">{data.samples ?? '…'}</span> 个样本
          </>
        )}
      </div>
    </div>
  );
});

export const ServerNode = memo(function ServerNode({ data, selected }: NodeProps<TopologyNode>) {
  return (
    <div className={`server-node ${selected ? 'is-selected' : ''}`}>
      <Handle id="left" type="target" position={Position.Left} />
      <Handle id="right" type="target" position={Position.Right} />
      <span className="server-node-icon">
        <Server size={32} />
      </span>
      <strong>全局服务器</strong>
      <span className="server-algorithm mono">
        {modelNames[data.model ?? 'lr']} · {data.algorithm}
      </span>
      <div className="server-round mono">
        {data.round ?? 0} / {data.rounds ?? 0} 轮
      </div>
      <div className="server-phase">{data.phase ?? '准备训练'}</div>
    </div>
  );
});
