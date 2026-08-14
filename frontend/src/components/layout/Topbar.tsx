import { Menu, Search, Settings } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import type { FormEvent } from "react";

export function Topbar({ onOpenNav }: { onOpenNav: () => void }) {
  const navigate = useNavigate();

  function onSearch(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const q = String(data.get("q") || "").trim();
    navigate(q ? `/scans?q=${encodeURIComponent(q)}` : "/scans");
  }

  return (
    <header className="flex h-14 items-center justify-between gap-3 border-b border-line px-4 lg:px-6">
      <button
        type="button"
        className="rounded-lg p-2 text-mute hover:bg-white/5 lg:hidden"
        aria-label="Open navigation"
        onClick={onOpenNav}
      >
        <Menu className="h-5 w-5" />
      </button>
      <form onSubmit={onSearch} className="relative min-w-0 flex-1 max-w-md">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-faint" aria-hidden />
        <input
          name="q"
          type="search"
          placeholder="Search scans…"
          aria-label="Search scans"
          className="w-full rounded-lg border border-line bg-panel py-2 pl-9 pr-3 text-sm text-ink placeholder:text-faint"
        />
      </form>
      <div className="flex items-center gap-3">
        <div className="hidden text-xs text-mute sm:block">Local analysis · no cloud upload</div>
        <Link to="/settings" aria-label="Settings" className="rounded-lg p-2 text-mute hover:bg-white/5">
          <Settings className="h-4 w-4" />
        </Link>
      </div>
    </header>
  );
}
