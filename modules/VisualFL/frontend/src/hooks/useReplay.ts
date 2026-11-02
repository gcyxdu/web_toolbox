import { useEffect, useMemo, useState } from 'react';
import type { RunEvent } from '../types';

export function useReplay(events: RunEvent[], runId?: string) {
  const [replaying, setReplaying] = useState(false);
  const [playing, setPlaying] = useState(false);
  const [replayIndex, setReplayIndex] = useState(0);
  const [speed, setSpeed] = useState(1);
  useEffect(() => {
    setReplaying(false);
    setPlaying(false);
    setReplayIndex(0);
  }, [runId]);
  useEffect(() => {
    if (!playing || !replaying) return;
    const timer = setInterval(
      () => setReplayIndex((index) => Math.min(events.length, index + 2 * speed)),
      150,
    );
    return () => clearInterval(timer);
  }, [playing, replaying, events.length, speed]);
  useEffect(() => {
    if (playing && replayIndex >= events.length) setPlaying(false);
  }, [playing, replayIndex, events.length]);
  const visibleEvents = useMemo(
    () => (replaying ? events.slice(0, replayIndex) : events),
    [events, replaying, replayIndex],
  );
  const replay = () => {
    setReplaying(true);
    setReplayIndex(0);
    setPlaying(true);
  };
  return {
    replaying,
    setReplaying,
    playing,
    setPlaying,
    replayIndex,
    setReplayIndex,
    speed,
    setSpeed,
    visibleEvents,
    replay,
  };
}
