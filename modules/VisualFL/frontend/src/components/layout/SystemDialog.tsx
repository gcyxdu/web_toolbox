import { Dialog, Button } from '@radix-ui/themes';
import HardwarePanel from './HardwarePanel';

export default function SystemDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Content maxWidth="680px" className="system-dialog">
        <Dialog.Title>本机配置</Dialog.Title>
        <Dialog.Description className="sr-only">查看本机硬件和实际训练设备。</Dialog.Description>
        <HardwarePanel />
        <div className="dialog-actions">
          <Dialog.Close>
            <Button>完成</Button>
          </Dialog.Close>
        </div>
      </Dialog.Content>
    </Dialog.Root>
  );
}
