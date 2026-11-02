import { Network as Graph } from '../icons/EvaIcons';
import ClientDevice from '../icons/ClientDevice';
import { useMemo, useState, useCallback, useRef, useEffect } from 'react';
import {
  Background,
  BackgroundVariant,
  Controls,
  ReactFlow,
  applyNodeChanges,
  type NodeChange,
  type Edge,
} from '@xyflow/react';
import { Eye, EyeSlash } from '@phosphor-icons/react';
import { Button, SegmentedControl } from '@radix-ui/themes';
import { ClientNode, ServerNode, type TopologyNode } from './Nodes';
import AutoFit from './AutoFit';
import RoutingEdge from './RoutingEdge';
import { buildTopologyNodes } from './topologyLayout';
import type { DataPreview, ExperimentConfig, Projection } from '../../types';

const edgeTypes = { routed: RoutingEdge };
const nodeTypes = { client: ClientNode, server: ServerNode };
export default function Topology({
  config,
  data,
  projection,
  selected,
  onSelect,
}: {
  config: ExperimentConfig;
  data: DataPreview | null;
  projection: Projection;
  selected: string;
  onSelect: (id: string) => void;
}) {
  const [showRoles, setShowRoles] = useState(true);
  const canvas = useRef<HTMLDivElement>(null);
  const [canvasWidth, setCanvasWidth] = useState(0);
  const [view, setView] = useState('topology');
  const [positions, setPositions] = useState<Record<string, { x: number; y: number }>>({});
  const [measurements, setMeasurements] = useState<Record<string, TopologyNode['measured']>>({});
  useEffect(() => {
    if (!canvas.current || view !== 'topology') return;
    const observer = new ResizeObserver((entries) =>
      setCanvasWidth(Math.round(entries[0].contentRect.width)),
    );
    observer.observe(canvas.current);
    return () => observer.disconnect();
  }, [view]);
  const nodes = useMemo(
    () =>
      buildTopologyNodes({
        config,
        data,
        projection,
        positions,
        measurements,
        selected,
        showRoles,
        canvasWidth,
      }),
    [config, data, projection, positions, measurements, selected, showRoles, canvasWidth],
  );
  const edges = useMemo<Edge[]>(
    () =>
      config.clients.map((client, i) => ({
        id: `edge-${client.id}`,
        source: client.id,
        target: 'server',
        targetHandle: i < Math.ceil(config.client_count / 2) ? 'left' : 'right',
        type: 'routed',
        pathOptions: { borderRadius: 20, offset: 28 },
        zIndex: selected === client.id ? 2 : 0,
        animated: ['training', 'uploaded'].includes(projection.clients[client.id]?.state ?? ''),
        style: {
          stroke:
            showRoles && client.malicious && config.attack !== 'None'
              ? '#CC7C71'
              : selected === client.id
                ? '#448d81'
                : '#b5cdd1',
          strokeWidth: selected === client.id ? 2.2 : 1.5,
          opacity: selected !== 'server' && selected !== client.id ? 0.5 : 1,
        },
      })),
    [config, projection.clients, showRoles, selected],
  );
  const onNodesChange = useCallback(
    (changes: NodeChange<TopologyNode>[]) => {
      const moved = applyNodeChanges(changes, nodes);
      if (changes.some((change) => change.type === 'dimensions'))
        setMeasurements(Object.fromEntries(moved.map((node) => [node.id, node.measured])));
      if (changes.some((change) => change.type === 'position'))
        setPositions(Object.fromEntries(moved.map((node) => [node.id, node.position])));
    },
    [nodes],
  );

  return (
    <section className="topology-panel">
      <div className="panel-toolbar">
        <div className="panel-title">
          <Graph size={17} />
          <strong>联邦拓扑</strong>
          <span className="subtle-label">同步星形</span>
        </div>
        <SegmentedControl.Root size="1" value={view} onValueChange={setView}>
          <SegmentedControl.Item value="topology">拓扑</SegmentedControl.Item>
          <SegmentedControl.Item value="clients">客户端</SegmentedControl.Item>
        </SegmentedControl.Root>
      </div>
      <div className="topology-subbar">
        <span>
          <span className="legend-dot normal" />
          良性客户端
          <span className="legend-dot attack" />
          恶意客户端
          {projection.layersift && (
            <span className="layersift-round-result">
              LayerSift · 第 {projection.layersift.round} 轮 · 入选{' '}
              {projection.layersift.selected_count}/{projection.layersift.participant_count}
            </span>
          )}
        </span>
        <Button
          variant="ghost"
          size="1"
          color="gray"
          onClick={() => setShowRoles((value) => !value)}
        >
          {showRoles ? <Eye size={14} /> : <EyeSlash size={14} />}
          {showRoles ? '隐藏角色' : '显示角色'}
        </Button>
      </div>
      {view === 'topology' ? (
        <div className="topology-canvas" data-testid="topology-canvas" ref={canvas}>
          <ReactFlow
            key={`${config.client_count}-${canvasWidth >= 480 ? 'compact' : 'regular'}`}
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            edgeTypes={edgeTypes}
            fitView
            fitViewOptions={{ padding: 0.08 }}
            minZoom={0.15}
            maxZoom={1.8}
            onNodeClick={(_, node) => onSelect(node.id)}
            onNodesChange={onNodesChange}
            nodesConnectable={false}
            deleteKeyCode={null}
            colorMode="light"
            proOptions={{ hideAttribution: true }}
          >
            <Background color="#d3e3e4" gap={24} size={1} variant={BackgroundVariant.Dots} />
            <AutoFit
              layoutKey={`${config.client_count}-${canvasWidth >= 480 ? 'compact' : 'regular'}`}
            />
            <Controls showInteractive={false} />
          </ReactFlow>
        </div>
      ) : (
        <div className="client-grid">
          {config.clients.map((client) => (
            <button
              key={client.id}
              className={`${selected === client.id ? 'selected' : ''} ${showRoles && client.malicious && config.attack !== 'None' ? 'is-attacker' : ''}`}
              onClick={() => onSelect(client.id)}
            >
              <ClientDevice
                size={34}
                malicious={showRoles && client.malicious && config.attack !== 'None'}
              />
              <strong>Client {client.id.split('-')[1]}</strong>
              {projection.clients[client.id]?.selected !== undefined && (
                <small
                  className={`node-selection ${projection.clients[client.id].selected ? 'included' : 'excluded'}`}
                >
                  {projection.clients[client.id].selected ? '入选聚合' : '未入选'}
                </small>
              )}
              <span>
                {data?.clients.find((item) => item.id === client.id)?.samples ?? '…'} 个样本
              </span>
              <small>
                {showRoles && client.malicious && config.attack !== 'None'
                  ? config.attack
                  : '客户端'}
              </small>
            </button>
          ))}
        </div>
      )}
    </section>
  );
}
