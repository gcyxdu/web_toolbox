import { BaseEdge, Position, useInternalNode, type EdgeProps } from '@xyflow/react';

type Point = { x: number; y: number };

function roundedPath(points: Point[]) {
  const clean = points.filter(
    (point, index) =>
      !index || Math.hypot(point.x - points[index - 1].x, point.y - points[index - 1].y) > 0.1,
  );
  let path = `M ${clean[0].x} ${clean[0].y}`;
  for (let i = 1; i < clean.length - 1; i++) {
    const a = clean[i - 1],
      b = clean[i],
      c = clean[i + 1];
    const before = Math.hypot(b.x - a.x, b.y - a.y),
      after = Math.hypot(c.x - b.x, c.y - b.y);
    const radius = Math.min(8, before / 2, after / 2);
    const entry = {
      x: b.x + ((a.x - b.x) * radius) / before,
      y: b.y + ((a.y - b.y) * radius) / before,
    };
    const exit = {
      x: b.x + ((c.x - b.x) * radius) / after,
      y: b.y + ((c.y - b.y) * radius) / after,
    };
    path += ` L ${entry.x} ${entry.y} Q ${b.x} ${b.y} ${exit.x} ${exit.y}`;
  }
  const last = clean[clean.length - 1];
  return `${path} L ${last.x} ${last.y}`;
}

export default function RoutingEdge({
  id,
  source,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  style,
  markerEnd,
}: EdgeProps) {
  const node = useInternalNode(source);
  const direction = sourcePosition === Position.Right ? 1 : -1;
  const busX = targetX - direction * 24;
  const points: Point[] = [{ x: sourceX, y: sourceY }];
  if (node?.data.outerColumn) {
    // Outer-column connections use the empty gutter below their own row,
    // never the interior of the neighboring client card.
    const gutterY = sourceY + (node.measured.height ?? 80) / 2 + 11;
    const gutterX = sourceX + direction * 12;
    points.push({ x: gutterX, y: sourceY }, { x: gutterX, y: gutterY }, { x: busX, y: gutterY });
  } else {
    points.push({ x: busX, y: sourceY });
  }
  points.push({ x: busX, y: targetY }, { x: targetX, y: targetY });
  return (
    <BaseEdge
      id={id}
      path={roundedPath(points)}
      style={style}
      markerEnd={markerEnd}
      interactionWidth={12}
    />
  );
}
