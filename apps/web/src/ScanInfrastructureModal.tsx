import { CliWorkflowDialog } from "./components/CliWorkflow";

export function ScanInfrastructureModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  return <CliWorkflowDialog workflow="scan" isOpen={isOpen} onClose={onClose} />;
}
