import type { DataPreview, ExperimentConfig, Projection } from '../../types';
import type { TopologyNode } from './Nodes';

type LayoutInput = {
  config: ExperimentConfig;
  data: DataPreview | null;
  projection: Projection;
  positions: Record<string, { x: number; y: number }>;
  measurements: Record<string, TopologyNode['measured']>;
  selected: string;
  showRoles: boolean;
  canvasWidth: number;
};

export function buildTopologyNodes({
  config,
  data,
  projection,
  positions,
  measurements,
  selected,
  showRoles,
  canvasWidth,
}: LayoutInput): TopologyNode[] {
  const perSide = Math.ceil(config.client_count / 2);
  const columns = config.client_count >= 10 && canvasWidth >= 480 ? 2 : 1;
  const rows = Math.ceil(perSide / columns);
  const height = (rows - 1) * 100;
  const clients: TopologyNode[] = config.clients.map((client, i) => {
    const left = i < perSide;
    const index = left ? i : i - perSide;
    const column = Math.floor(index / rows);
    const row = index % rows;
    return {
      id: client.id,
      type: 'client',
      measured: measurements[client.id],
      position: positions[client.id] ?? {
        x: left ? column * 184 : (columns === 1 ? 530 : 620) + column * 184,
        y: row * 100,
      },
      selected: selected === client.id,
      data: {
        label: `Client ${client.id.split('-')[1]}`,
        malicious: client.malicious && config.attack !== 'None',
        showRoles,
        samples: data?.clients.find((item) => item.id === client.id)?.samples,
        state: projection.clients[client.id]?.state,
        included: projection.clients[client.id]?.selected,
        side: left ? 'left' : 'right',
        outerColumn: columns > 1 && (left ? column === 0 : column === columns - 1),
      },
    };
  });
  return [
    {
      id: 'server',
      type: 'server',
      measured: measurements.server,
      position: positions.server ?? {
        x: columns === 1 ? 265 : 388,
        y: Math.max(
          0,
          height / 2 +
            ((measurements[config.clients[0]?.id]?.height ?? 80) -
              (measurements.server?.height ?? 176)) /
              2,
        ),
      },
      selected: selected === 'server',
      data: {
        label: '全局服务器',
        algorithm: config.algorithm,
        model: config.model ?? 'lr',
        phase: projection.phase,
        round: projection.round,
        rounds: config.rounds,
      },
    },
    ...clients,
  ];
}
