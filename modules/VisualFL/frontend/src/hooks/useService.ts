import { useEffect, useState, type Dispatch, type SetStateAction } from 'react';
import { api } from '../api';
import type { Catalog, Run } from '../types';

export function useService(setError: Dispatch<SetStateAction<string>>) {
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  const [runs, setRuns] = useState<Run[]>([]);
  const [connected, setConnected] = useState(false);
  useEffect(() => {
    let disposed = false;
    const load = async () => {
      try {
        const [cat, history] = await Promise.all([api.catalog(), api.runs()]);
        if (!disposed) {
          setCatalog(cat);
          setRuns(history);
          setConnected(true);
          setError((old) => (old.startsWith('后端连接失败') ? '' : old));
        }
      } catch (e) {
        if (!disposed) {
          setConnected(false);
          setError(`后端连接失败，请启动本地服务。${String(e)}`);
        }
      }
    };
    void load();
    const timer = setInterval(() => void load(), 5000);
    return () => {
      disposed = true;
      clearInterval(timer);
    };
  }, [setError]);
  return { catalog, runs, setRuns, connected };
}
