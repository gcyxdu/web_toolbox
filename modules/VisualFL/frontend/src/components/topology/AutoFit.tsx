import { useEffect } from 'react';
import { useNodesInitialized, useReactFlow, useStore } from '@xyflow/react';

export default function AutoFit({ layoutKey }: { layoutKey: string }) {
  const { fitView } = useReactFlow();
  const initialized = useNodesInitialized();
  const width = useStore((state) => state.width);
  const height = useStore((state) => state.height);
  useEffect(() => {
    if (!initialized || !width || !height) return;
    // Fit after React Flow has committed its own viewport measurements.
    const frame = requestAnimationFrame(() => void fitView({ padding: 0.08, duration: 0 }));
    return () => cancelAnimationFrame(frame);
  }, [fitView, initialized, width, height, layoutKey]);
  return null;
}
