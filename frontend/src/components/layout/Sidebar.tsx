import { NavLink } from "react-router-dom";
import {
  FolderSearch,
  Gauge,
  Layers,
  Plus,
  Settings,
  Shield,
} from "lucide-react";

const LINKS = [
  { to: "/", label: "Dashboard", icon: Gauge, end: true },
  { to: "/scans", label: "Scans", icon: FolderSearch, end: false },
  { to: "/reports", label: "Reports", icon: Shield, end: true },
  { to: "/technologies", label: "Technologies", icon: Layers, end: true },
  { to: "/settings", label: "Settings", icon: Settings, end: true },
];

type Props = {
  open?: boolean;
  onNavigate?: () => void;
};

export function Sidebar({ open = false, onNavigate }: Props) {
  return (
    <aside
      className={`fixed inset-y-0 left-0 z-30 flex w-60 shrink-0 flex-col border-r border-line bg-sidebar transition-transform lg:static lg:translate-x-0 ${
        open ? "translate-x-0" : "-translate-x-full"
      }`}
    >
      <div className="flex items-center gap-3 px-5 py-5">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-accent-soft text-sm font-semibold text-accent">
          AP
        </div>
        <div>
          <div className="text-sm font-semibold tracking-tight">AppProbe</div>
          <div className="text-[11px] uppercase tracking-[0.16em] text-faint">Static analysis</div>
        </div>
      </div>
      <NavLink
        to="/scans/new"
        onClick={onNavigate}
        className="mx-4 mb-4 inline-flex items-center justify-center gap-2 rounded-lg bg-accent px-3 py-2 text-sm font-medium text-canvas transition hover:brightness-110"
      >
        <Plus className="h-4 w-4" aria-hidden />
        New Scan
      </NavLink>
      <nav className="flex flex-1 flex-col gap-1 px-3" aria-label="Primary">
        {LINKS.map((link) => (
          <NavLink
            key={link.to}
            to={link.to}
            end={link.end}
            onClick={onNavigate}
            className={({ isActive }) =>
              `flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition ${
                isActive ? "bg-white/6 text-ink" : "text-mute hover:bg-white/4 hover:text-ink"
              }`
            }
          >
            <link.icon className="h-4 w-4" aria-hidden />
            {link.label}
          </NavLink>
        ))}
      </nav>
      <div className="border-t border-line px-5 py-4 text-[11px] text-faint">
        Milestone 2.9 · Local-first
      </div>
    </aside>
  );
}
