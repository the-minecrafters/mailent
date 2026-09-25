import { CliWorkflowDialog } from "./components/CliWorkflow";

/** Compatibility entry point: acquisition now happens in the local CLI. */
export function NewAssessmentModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  return <CliWorkflowDialog workflow="analyze" isOpen={isOpen} onClose={onClose} />;
}
