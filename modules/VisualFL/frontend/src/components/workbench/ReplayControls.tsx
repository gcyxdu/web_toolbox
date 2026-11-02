import { Pause, Play, ClockCounterClockwise } from '@phosphor-icons/react';
import { Button, IconButton } from '@radix-ui/themes';
import type { useWorkbench } from '../../hooks/useWorkbench';

export default function ReplayControls({ work }: { work: ReturnType<typeof useWorkbench> }) {
  if (!work.selectedRun || work.active || !work.events.length) return null;
  return (
    <div className="replay-controls">
      <ClockCounterClockwise size={16} />
      {!work.replaying ? (
        <>
          <span>事件已保存，可查看真实训练过程。</span>
          <Button variant="ghost" size="1" onClick={work.replay}>
            回放实验
            <Play size={12} weight="fill" />
          </Button>
        </>
      ) : (
        <>
          <strong>历史回放</strong>
          <IconButton
            size="1"
            variant="ghost"
            aria-label={work.playing ? '暂停回放' : '继续回放'}
            onClick={() => work.setPlaying((value) => !value)}
          >
            {work.playing ? <Pause size={15} /> : <Play size={15} />}
          </IconButton>
          <input
            aria-label="回放进度"
            type="range"
            min="0"
            max={work.events.length}
            value={work.replayIndex}
            onChange={(e) => {
              work.setPlaying(false);
              work.setReplayIndex(Number(e.target.value));
            }}
          />
          <select
            aria-label="回放速度"
            value={work.speed}
            onChange={(e) => work.setSpeed(Number(e.target.value))}
          >
            <option value="1">1×</option>
            <option value="2">2×</option>
            <option value="4">4×</option>
          </select>
          <Button
            size="1"
            variant="ghost"
            onClick={() => {
              work.setReplaying(false);
              work.setPlaying(false);
            }}
          >
            回到结果
          </Button>
        </>
      )}
    </div>
  );
}
