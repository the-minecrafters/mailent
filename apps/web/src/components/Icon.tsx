import {
  Activity,
  Archive,
  ArrowLeft,
  ArrowLeftRight,
  Check,
  CheckCircle2,
  ChevronRight,
  CircleAlert,
  Copy,
  Download,
  FileText,
  FileUp,
  FolderOpen,
  Info,
  LayoutDashboard,
  ListChecks,
  LockKeyhole,
  LogOut,
  type LucideIcon,
  Mail,
  Menu,
  Monitor,
  Plus,
  Printer,
  Radio,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldCheck,
  TriangleAlert,
  User,
  Wrench,
  X,
} from "lucide-react";
import type { CSSProperties } from "react";

const icons: Record<string, LucideIcon> = {
  logout: LogOut,
  grid_view: LayoutDashboard,
  shield: Shield,
  dns: Server,
  swap_horiz: ArrowLeftRight,
  warning: TriangleAlert,
  search: Search,
  build: Wrench,
  rule: ListChecks,
  description: FileText,
  sync_alt: ArrowLeftRight,
  sensors: Radio,
  folder_open: FolderOpen,
  upload_file: FileUp,
  archive: Archive,
  arrow_back: ArrowLeft,
  article: FileText,
  check_circle: CheckCircle2,
  download: Download,
  lock: LockKeyhole,
  print: Printer,
  security: ShieldCheck,
  verified_user: ShieldCheck,
  person: User,
  close: X,
  error: CircleAlert,
  mail: Mail,
  computer: Monitor,
  menu: Menu,
  chevron_right: ChevronRight,
  refresh: RefreshCw,
  add: Plus,
  info: Info,
  content_copy: Copy,
  check: Check,
  monitoring: Activity,
  devices: Monitor,
  phonelink_lock: LockKeyhole,
  block: CircleAlert,
};
export interface IconProps {
  name: string;
  size?: number | string;
  className?: string;
  style?: CSSProperties;
}
export function Icon({ name, size = 18, className = "", style }: IconProps) {
  const Glyph = icons[name] ?? FileText;
  return (
    <Glyph
      size={size}
      className={`icon ${className}`}
      strokeWidth={1.7}
      aria-hidden="true"
      style={{ flexShrink: 0, ...style }}
    />
  );
}
