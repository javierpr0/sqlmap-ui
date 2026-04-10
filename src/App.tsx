import { useState, useRef, useEffect, useCallback, useMemo } from "react";
import { Command } from "@tauri-apps/plugin-shell";
import {
  isPermissionGranted,
  requestPermission,
  sendNotification,
} from "@tauri-apps/plugin-notification";
import { check } from "@tauri-apps/plugin-updater";
import Database from "@tauri-apps/plugin-sql";

// ── Types ──────────────────────────────────────────────

interface TerminalLine {
  text: string;
  type: "stdout" | "stderr" | "info" | "cmd" | "success";
}

interface SqlmapConfig {
  targetUrl: string;
  data: string;
  cookie: string;
  headers: string;
  method: string;
  level: number;
  risk: number;
  threads: number;
  dbms: string;
  technique: string;
  tamper: string;
  flags: {
    batch: boolean;
    forms: boolean;
    dbs: boolean;
    tables: boolean;
    dump: boolean;
    currentDb: boolean;
    currentUser: boolean;
    passwords: boolean;
    randomAgent: boolean;
    tor: boolean;
  };
  extraArgs: string;
}

interface ScanTab {
  id: string;
  label: string;
  config: SqlmapConfig;
  output: TerminalLine[];
  isRunning: boolean;
  initializing: boolean;
  viewMode: "output" | "command" | "requests" | "findings";
  startedAt?: number;
  finishedAt?: number;
}

interface Finding {
  parameter: string;
  type: string;
  title: string;
  payload: string;
}

interface HistoryEntry {
  id: string;
  targetUrl: string;
  config: SqlmapConfig;
  output: TerminalLine[];
  startedAt: number;
  finishedAt: number;
  exitCode: number | null;
}

interface Profile {
  name: string;
  config: SqlmapConfig;
}

type ChildProcess = Awaited<ReturnType<Command<string>["spawn"]>>;

// ── Defaults ───────────────────────────────────────────

const DEFAULT_CONFIG: SqlmapConfig = {
  targetUrl: "",
  data: "",
  cookie: "",
  headers: "",
  method: "GET",
  level: 1,
  risk: 1,
  threads: 1,
  dbms: "",
  technique: "",
  tamper: "",
  flags: {
    batch: true,
    forms: false,
    dbs: false,
    tables: false,
    dump: false,
    currentDb: false,
    currentUser: false,
    passwords: false,
    randomAgent: false,
    tor: false,
  },
  extraArgs: "",
};

// ── Helpers ────────────────────────────────────────────

let tabCounter = 1;

function createTab(): ScanTab {
  const id = `tab-${tabCounter}`;
  const label = `Scan ${tabCounter}`;
  tabCounter++;
  return {
    id,
    label,
    config: { ...DEFAULT_CONFIG, flags: { ...DEFAULT_CONFIG.flags } },
    output: [],
    isRunning: false,
    initializing: false,
    viewMode: "output",
  };
}

function getTabLabel(tab: ScanTab): string {
  if (tab.config.targetUrl) {
    try {
      const url = new URL(tab.config.targetUrl);
      return url.hostname.replace(/^www\./, "");
    } catch {
      return tab.label;
    }
  }
  return tab.label;
}

function classifyLine(text: string): string {
  if (/\[CRITICAL\]/.test(text)) return "terminal-line critical";
  if (/\[ERROR\]/.test(text)) return "terminal-line error";
  if (/\[WARNING\]/.test(text)) return "terminal-line warning";
  if (/\[INFO\]/.test(text)) return "terminal-line info-tag";
  if (/injectable|vulnerable/i.test(text)) return "terminal-line success";
  if (/^---/.test(text) || /^Parameter:/.test(text)) return "terminal-line highlight";
  return "terminal-line";
}

function isHttpRequest(text: string): boolean {
  return /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+/.test(text.trim()) ||
    /^HTTP\/\d/.test(text.trim()) ||
    /^Host:|^Cookie:|^Content-Type:|^User-Agent:|^Accept:|^Referer:/i.test(text.trim());
}

function parseRawRequest(raw: string): Partial<SqlmapConfig> {
  const lines = raw.trim().split("\n");
  const result: Partial<SqlmapConfig> = {};
  if (lines.length === 0) return result;

  const firstLine = lines[0].trim();
  const methodMatch = firstLine.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)/i);

  let host = "";
  const headers: string[] = [];
  let bodyStartIdx = -1;

  for (let i = 1; i < lines.length; i++) {
    if (lines[i].trim() === "") {
      bodyStartIdx = i + 1;
      break;
    }
    const [key, ...valueParts] = lines[i].split(":");
    const value = valueParts.join(":").trim();
    const keyLower = key.trim().toLowerCase();

    if (keyLower === "host") {
      host = value;
    } else if (keyLower === "cookie") {
      result.cookie = value;
    } else {
      headers.push(`${key.trim()}: ${value}`);
    }
  }

  if (methodMatch) {
    result.method = methodMatch[1].toUpperCase();
    const path = methodMatch[2];
    if (host) {
      const proto = path.startsWith("https") ? "" : "https://";
      result.targetUrl = path.startsWith("http") ? path : `${proto}${host}${path}`;
    } else {
      result.targetUrl = path;
    }
  }

  if (headers.length > 0) {
    result.headers = headers.join("\\n");
  }

  if (bodyStartIdx > 0 && bodyStartIdx < lines.length) {
    result.data = lines.slice(bodyStartIdx).join("\n").trim();
  }

  return result;
}

let db: Awaited<ReturnType<typeof Database.load>> | null = null;

async function getDb() {
  if (!db) db = await Database.load("sqlite:sqlmap-ui.db");
  return db;
}

async function loadHistoryFromDb(): Promise<HistoryEntry[]> {
  try {
    const d = await getDb();
    const rows = await d.select<Array<{ id: string; target_url: string; config: string; output: string; started_at: number; finished_at: number; exit_code: number | null }>>(
      "SELECT * FROM scan_history ORDER BY started_at DESC LIMIT 50"
    );
    return rows.map((r) => ({
      id: r.id,
      targetUrl: r.target_url,
      config: JSON.parse(r.config),
      output: JSON.parse(r.output),
      startedAt: r.started_at,
      finishedAt: r.finished_at,
      exitCode: r.exit_code,
    }));
  } catch {
    return [];
  }
}

async function saveHistoryEntry(entry: HistoryEntry) {
  try {
    const d = await getDb();
    await d.execute(
      "INSERT OR REPLACE INTO scan_history (id, target_url, config, output, started_at, finished_at, exit_code) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [entry.id, entry.targetUrl, JSON.stringify(entry.config), JSON.stringify(entry.output), entry.startedAt, entry.finishedAt, entry.exitCode]
    );
  } catch { /* ignore */ }
}

async function clearHistoryDb() {
  try {
    const d = await getDb();
    await d.execute("DELETE FROM scan_history");
  } catch { /* ignore */ }
}

async function loadProfilesFromDb(): Promise<Profile[]> {
  try {
    const d = await getDb();
    const rows = await d.select<Array<{ name: string; config: string }>>(
      "SELECT * FROM profiles ORDER BY name"
    );
    return rows.map((r) => ({ name: r.name, config: JSON.parse(r.config) }));
  } catch {
    return [];
  }
}

async function saveProfileToDb(profile: Profile) {
  try {
    const d = await getDb();
    await d.execute(
      "INSERT OR REPLACE INTO profiles (name, config) VALUES (?, ?)",
      [profile.name, JSON.stringify(profile.config)]
    );
  } catch { /* ignore */ }
}

async function deleteProfileFromDb(name: string) {
  try {
    const d = await getDb();
    await d.execute("DELETE FROM profiles WHERE name = ?", [name]);
  } catch { /* ignore */ }
}

function exportReportHTML(entry: HistoryEntry | ScanTab): string {
  const config = entry.config;
  const output = entry.output;
  const date = "startedAt" in entry && entry.startedAt
    ? new Date(entry.startedAt).toLocaleString()
    : new Date().toLocaleString();

  const lines = output.map((l) => {
    let cls = "";
    if (/\[CRITICAL\]/.test(l.text)) cls = "color:#f85149";
    else if (/\[ERROR\]/.test(l.text)) cls = "color:#f85149";
    else if (/\[WARNING\]/.test(l.text)) cls = "color:#d29922";
    else if (/\[INFO\]/.test(l.text)) cls = "color:#58a6ff";
    else if (/injectable|vulnerable/i.test(l.text)) cls = "color:#3fb950;font-weight:bold";
    else if (l.type === "cmd") cls = "color:#58a6ff;font-weight:bold";
    else if (l.type === "stderr") cls = "color:#f85149";
    else cls = "color:#c9d1d9";
    const escaped = l.text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    return `<div style="${cls}">${escaped}</div>`;
  }).join("\n");

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>SQLMap Report - ${config.targetUrl}</title>
<style>
body{background:#0d1117;color:#e6edf3;font-family:-apple-system,sans-serif;padding:40px;max-width:1200px;margin:0 auto}
h1{font-size:22px;margin-bottom:4px}
.meta{color:#8b949e;font-size:13px;margin-bottom:24px}
.config{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin-bottom:24px;font-size:13px}
.config dt{color:#8b949e;float:left;width:120px}
.config dd{margin-left:130px;margin-bottom:4px}
.output{background:#010409;border:1px solid #30363d;border-radius:8px;padding:16px;font-family:"SF Mono","Fira Code",monospace;font-size:12px;line-height:1.6;overflow-x:auto}
</style></head><body>
<h1>SQLMap Scan Report</h1>
<div class="meta">${date} | ${config.targetUrl}</div>
<div class="config">
<dl>
<dt>Target</dt><dd>${config.targetUrl}</dd>
${config.data ? `<dt>POST Data</dt><dd>${config.data}</dd>` : ""}
${config.cookie ? `<dt>Cookie</dt><dd>${config.cookie}</dd>` : ""}
<dt>Level / Risk</dt><dd>${config.level} / ${config.risk}</dd>
<dt>Threads</dt><dd>${config.threads}</dd>
${config.dbms ? `<dt>DBMS</dt><dd>${config.dbms}</dd>` : ""}
${config.technique ? `<dt>Technique</dt><dd>${config.technique}</dd>` : ""}
${config.tamper ? `<dt>Tamper</dt><dd>${config.tamper}</dd>` : ""}
</dl>
</div>
<div class="output">${lines}</div>
<div class="meta" style="margin-top:24px">Generated by SQLMap UI</div>
</body></html>`;
}

// ── Batch targets ──────────────────────────────────────

interface BatchTarget {
  url: string;
  status: "pending" | "running" | "done" | "error";
}

// ── App Component ──────────────────────────────────────

export default function App() {
  const [tabs, setTabs] = useState<ScanTab[]>(() => [createTab()]);
  const [activeTabId, setActiveTabId] = useState<string>("tab-1");
  const terminalRef = useRef<HTMLDivElement>(null);
  const childRefs = useRef<Map<string, ChildProcess>>(new Map());

  // Theme
  const [theme, setTheme] = useState<"dark" | "light">(() => {
    return (localStorage.getItem("sqlmap-theme") as "dark" | "light") || "dark";
  });

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("sqlmap-theme", theme);
  }, [theme]);

  // Search
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const searchInputRef = useRef<HTMLInputElement>(null);

  // Panels
  const [showHistory, setShowHistory] = useState(false);
  const [showProfiles, setShowProfiles] = useState(false);
  const [showImport, setShowImport] = useState(false);
  const [showBatch, setShowBatch] = useState(false);

  // History & Profiles (loaded from SQLite)
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [profileName, setProfileName] = useState("");

  // Import
  const [rawRequest, setRawRequest] = useState("");

  // Batch
  const [batchUrls, setBatchUrls] = useState("");
  const [batchTargets, setBatchTargets] = useState<BatchTarget[]>([]);

  // Resize
  const [panelWidth, setPanelWidth] = useState(360);
  const resizing = useRef(false);

  const [updateAvailable, setUpdateAvailable] = useState<string | null>(null);

  const activeTab = tabs.find((t) => t.id === activeTabId) ?? tabs[0];

  // Check for updates on startup
  useEffect(() => {
    check().then((update) => {
      if (update) setUpdateAvailable(update.version);
    }).catch(() => {});
  }, []);

  // Load data from SQLite on startup
  useEffect(() => {
    loadHistoryFromDb().then(setHistory);
    loadProfilesFromDb().then(setProfiles);
  }, []);

  // Keyboard shortcuts
  const runRef = useRef(runSqlmap);
  const stopRef = useRef(stopSqlmap);
  runRef.current = runSqlmap;
  stopRef.current = stopSqlmap;

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      const mod = e.metaKey || e.ctrlKey;

      // Cmd+F: Search
      if (mod && e.key === "f") {
        e.preventDefault();
        setSearchOpen((prev) => !prev);
        setTimeout(() => searchInputRef.current?.focus(), 50);
        return;
      }
      // Cmd+R: Run scan
      if (mod && e.key === "r") {
        e.preventDefault();
        runRef.current();
        return;
      }
      // Cmd+.: Stop scan
      if (mod && e.key === ".") {
        e.preventDefault();
        stopRef.current();
        return;
      }
      // Cmd+T: New tab
      if (mod && e.key === "t") {
        e.preventDefault();
        addTab();
        return;
      }
      // Cmd+W: Close tab
      if (mod && e.key === "w") {
        e.preventDefault();
        setTabs((prev) => {
          if (prev.length <= 1) return prev;
          return prev; // handled below
        });
        closeTab(activeTabId);
        return;
      }
      // Escape: close search/modals
      if (e.key === "Escape") {
        setSearchOpen(false);
        setSearchQuery("");
        setShowHistory(false);
        setShowProfiles(false);
        setShowImport(false);
        setShowBatch(false);
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [activeTabId]);

  // Drag & drop files
  const [dragOver, setDragOver] = useState(false);

  function handleDrop(e: React.DragEvent) {
    e.preventDefault();
    setDragOver(false);
    const files = Array.from(e.dataTransfer.files);
    if (files.length === 0) return;

    const file = files[0];
    const reader = new FileReader();
    reader.onload = () => {
      const content = reader.result as string;
      if (file.name.endsWith(".txt")) {
        setBatchUrls(content);
        setShowBatch(true);
      } else {
        setRawRequest(content);
        setShowImport(true);
      }
    };
    reader.readAsText(file);
  }

  const scrollToBottom = useCallback(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, []);

  useEffect(() => {
    if (!searchQuery) scrollToBottom();
  }, [activeTab?.output, scrollToBottom, searchQuery]);

  // Resize handlers
  const startResize = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    resizing.current = true;
    const startX = e.clientX;
    const startWidth = panelWidth;

    function onMove(ev: MouseEvent) {
      if (!resizing.current) return;
      const newWidth = Math.max(280, Math.min(600, startWidth + ev.clientX - startX));
      setPanelWidth(newWidth);
    }
    function onUp() {
      resizing.current = false;
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
    }
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  }, [panelWidth]);

  // Parse findings from output
  const findings = useMemo((): Finding[] => {
    const result: Finding[] = [];
    let currentParam = "";
    let currentType = "";
    let currentTitle = "";

    for (const line of activeTab.output) {
      const paramMatch = line.text.match(/Parameter:\s+(.+)/);
      if (paramMatch) { currentParam = paramMatch[1].trim(); continue; }

      const typeMatch = line.text.match(/^\s*Type:\s+(.+)/);
      if (typeMatch) { currentType = typeMatch[1].trim(); continue; }

      const titleMatch = line.text.match(/^\s*Title:\s+(.+)/);
      if (titleMatch) { currentTitle = titleMatch[1].trim(); continue; }

      const payloadMatch = line.text.match(/^\s*Payload:\s+(.+)/);
      if (payloadMatch) {
        result.push({
          parameter: currentParam,
          type: currentType,
          title: currentTitle,
          payload: payloadMatch[1].trim(),
        });
        continue;
      }

      // Detect DBMS info
      const dbmsMatch = line.text.match(/back-end DBMS:\s+(.+)/);
      if (dbmsMatch && !result.some((f) => f.type === "DBMS Detected")) {
        result.push({ parameter: "-", type: "DBMS Detected", title: dbmsMatch[1].trim(), payload: "" });
      }
    }
    return result;
  }, [activeTab.output]);

  // Filtered output for search
  const filteredOutput = useMemo(() => {
    if (!searchQuery) return activeTab.output;
    const q = searchQuery.toLowerCase();
    return activeTab.output.filter((l) => l.text.toLowerCase().includes(q));
  }, [activeTab.output, searchQuery]);

  // Extracted HTTP requests from output
  const httpRequests = useMemo(() => {
    return activeTab.output.filter((l) => isHttpRequest(l.text));
  }, [activeTab.output]);

  function updateTab(tabId: string, updater: (tab: ScanTab) => ScanTab) {
    setTabs((prev) => prev.map((t) => (t.id === tabId ? updater(t) : t)));
  }

  function updateConfig<K extends keyof SqlmapConfig>(key: K, value: SqlmapConfig[K]) {
    updateTab(activeTabId, (t) => ({
      ...t,
      config: { ...t.config, [key]: value },
    }));
  }

  function toggleFlag(flag: keyof SqlmapConfig["flags"]) {
    updateTab(activeTabId, (t) => ({
      ...t,
      config: {
        ...t.config,
        flags: { ...t.config.flags, [flag]: !t.config.flags[flag] },
      },
    }));
  }

  function addTab() {
    const newTab = createTab();
    setTabs((prev) => [...prev, newTab]);
    setActiveTabId(newTab.id);
  }

  function closeTab(tabId: string) {
    const child = childRefs.current.get(tabId);
    if (child) {
      child.kill();
      childRefs.current.delete(tabId);
    }
    setTabs((prev) => {
      if (prev.length <= 1) return prev;
      const filtered = prev.filter((t) => t.id !== tabId);
      if (activeTabId === tabId) {
        const idx = prev.findIndex((t) => t.id === tabId);
        const newActive = filtered[Math.min(idx, filtered.length - 1)];
        setActiveTabId(newActive.id);
      }
      return filtered;
    });
  }

  function buildArgs(config: SqlmapConfig): string[] {
    const args: string[] = ["--disable-coloring"];
    if (config.targetUrl) args.push("-u", config.targetUrl);
    if (config.data) args.push("--data", config.data);
    if (config.cookie) args.push("--cookie", config.cookie);
    if (config.headers) {
      config.headers.split("\\n").forEach((h) => {
        if (h.trim()) args.push("--header", h.trim());
      });
    }
    if (config.method !== "GET" && config.method) args.push("--method", config.method);
    if (config.level > 1) args.push("--level", String(config.level));
    if (config.risk > 1) args.push("--risk", String(config.risk));
    if (config.threads > 1) args.push("--threads", String(config.threads));
    if (config.dbms) args.push("--dbms", config.dbms);
    if (config.technique) args.push("--technique", config.technique);
    if (config.tamper) args.push("--tamper", config.tamper);
    const { flags } = config;
    if (flags.batch) args.push("--batch");
    if (flags.forms) args.push("--forms");
    if (flags.dbs) args.push("--dbs");
    if (flags.tables) args.push("--tables");
    if (flags.dump) args.push("--dump");
    if (flags.currentDb) args.push("--current-db");
    if (flags.currentUser) args.push("--current-user");
    if (flags.passwords) args.push("--passwords");
    if (flags.randomAgent) args.push("--random-agent");
    if (flags.tor) args.push("--tor");
    if (config.extraArgs.trim()) {
      args.push(...config.extraArgs.trim().split(/\s+/));
    }
    return args;
  }

  function getCommandString(): string {
    return "sqlmap " + buildArgs(activeTab.config).join(" ");
  }

  async function sendSystemNotification(title: string, body: string) {
    let granted = await isPermissionGranted();
    if (!granted) {
      const permission = await requestPermission();
      granted = permission === "granted";
    }
    if (granted) sendNotification({ title, body });
  }

  async function runSqlmap(overrideTabId?: string, overrideConfig?: SqlmapConfig) {
    const tabId = overrideTabId || activeTabId;
    const tab = tabs.find((t) => t.id === tabId);
    const config = overrideConfig || tab?.config;
    if (!config || !config.targetUrl.trim()) return;

    const args = buildArgs(config);

    updateTab(tabId, (t) => ({
      ...t,
      config: overrideConfig || t.config,
      isRunning: true,
      initializing: true,
      viewMode: "output",
      startedAt: Date.now(),
      finishedAt: undefined,
      output: [
        { text: `$ sqlmap ${args.join(" ")}`, type: "cmd" },
        { text: "", type: "info" },
        { text: "Initializing sqlmap engine...", type: "info" },
      ],
    }));

    try {
      const command = Command.sidecar("binaries/sqlmap-sidecar", args);

      command.stdout.on("data", (line: string) => {
        updateTab(tabId, (t) => {
          const output = t.initializing
            ? t.output.filter((l) => l.text !== "Initializing sqlmap engine...")
            : t.output;
          return { ...t, initializing: false, output: [...output, { text: line, type: "stdout" }] };
        });
      });

      command.stderr.on("data", (line: string) => {
        updateTab(tabId, (t) => ({
          ...t,
          output: [...t.output, { text: line, type: "stderr" }],
        }));
      });

      command.on("close", (data) => {
        const exitCode = data.code;
        const finishedAt = Date.now();
        updateTab(tabId, (t) => {
          const newTab = {
            ...t,
            isRunning: false,
            finishedAt,
            output: [
              ...t.output,
              { text: "", type: "info" as const },
              { text: `Process exited with code ${exitCode}`, type: (exitCode === 0 ? "success" : "stderr") as TerminalLine["type"] },
            ],
          };
          // Save to history
          const entry: HistoryEntry = {
            id: `hist-${Date.now()}`,
            targetUrl: newTab.config.targetUrl,
            config: newTab.config,
            output: newTab.output,
            startedAt: newTab.startedAt || finishedAt,
            finishedAt,
            exitCode,
          };
          const updatedHistory = [entry, ...history].slice(0, 50);
          setHistory(updatedHistory);
          saveHistoryEntry(entry);
          return newTab;
        });
        childRefs.current.delete(tabId);
        sendSystemNotification(
          "Scan Complete",
          `${config.targetUrl} finished (exit code ${exitCode})`
        );
      });

      command.on("error", (error: string) => {
        updateTab(tabId, (t) => ({
          ...t,
          isRunning: false,
          output: [...t.output, { text: `Error: ${error}`, type: "stderr" }],
        }));
        childRefs.current.delete(tabId);
      });

      const child = await command.spawn();
      childRefs.current.set(tabId, child);
    } catch (err) {
      updateTab(tabId, (t) => ({
        ...t,
        isRunning: false,
        output: [...t.output, { text: `Failed to start: ${err}`, type: "stderr" }],
      }));
    }
  }

  async function stopSqlmap() {
    const child = childRefs.current.get(activeTabId);
    if (child) {
      await child.kill();
      childRefs.current.delete(activeTabId);
      updateTab(activeTabId, (t) => ({
        ...t,
        isRunning: false,
        output: [...t.output, { text: "", type: "info" }, { text: "Process killed by user", type: "stderr" }],
      }));
    }
  }

  function clearOutput() {
    updateTab(activeTabId, (t) => ({ ...t, output: [] }));
  }

  function setViewMode(mode: ScanTab["viewMode"]) {
    updateTab(activeTabId, (t) => ({ ...t, viewMode: mode }));
  }

  // Profile management
  function saveProfile() {
    if (!profileName.trim()) return;
    const newProfile: Profile = { name: profileName.trim(), config: { ...activeTab.config, flags: { ...activeTab.config.flags } } };
    const updated = [...profiles.filter((p) => p.name !== newProfile.name), newProfile];
    setProfiles(updated);
    saveProfileToDb(newProfile);
    setProfileName("");
    setShowProfiles(false);
  }

  function loadProfile(profile: Profile) {
    updateTab(activeTabId, (t) => ({
      ...t,
      config: { ...profile.config, flags: { ...profile.config.flags } },
    }));
    setShowProfiles(false);
  }

  function deleteProfile(name: string) {
    const updated = profiles.filter((p) => p.name !== name);
    setProfiles(updated);
    deleteProfileFromDb(name);
  }

  // Import raw request or Burp XML
  function applyImport() {
    const trimmed = rawRequest.trim();

    // Detect Burp Suite XML format
    if (trimmed.startsWith("<?xml") || trimmed.startsWith("<items")) {
      const parser = new DOMParser();
      const doc = parser.parseFromString(trimmed, "text/xml");
      const items = doc.querySelectorAll("item");

      if (items.length > 0) {
        const urls: string[] = [];
        items.forEach((item) => {
          const url = item.querySelector("url")?.textContent;
          if (url) urls.push(url);

          // Apply first item's details to current tab
          if (urls.length === 1) {
            const method = item.querySelector("method")?.textContent || "GET";
            const host = item.querySelector("host")?.textContent || "";
            const path = item.querySelector("path")?.textContent || "";
            const requestB64 = item.querySelector("request")?.textContent || "";

            let cookie = "";
            let headers = "";
            let data = "";

            // Try to decode base64 request
            if (requestB64) {
              try {
                const decoded = item.querySelector("request")?.getAttribute("base64") === "true"
                  ? atob(requestB64)
                  : requestB64;
                const parsed = parseRawRequest(decoded);
                cookie = parsed.cookie || "";
                headers = parsed.headers || "";
                data = parsed.data || "";
              } catch { /* ignore decode errors */ }
            }

            updateTab(activeTabId, (t) => ({
              ...t,
              config: {
                ...t.config,
                targetUrl: url || `https://${host}${path}`,
                method,
                cookie,
                headers,
                data,
                flags: { ...t.config.flags },
              },
            }));
          }
        });

        // If multiple items, open batch scan
        if (urls.length > 1) {
          setBatchUrls(urls.join("\n"));
          setShowBatch(true);
        }

        setRawRequest("");
        setShowImport(false);
        return;
      }
    }

    // Standard raw request
    const parsed = parseRawRequest(trimmed);
    updateTab(activeTabId, (t) => ({
      ...t,
      config: {
        ...t.config,
        ...parsed,
        flags: { ...t.config.flags },
      },
    }));
    setRawRequest("");
    setShowImport(false);
  }

  function exportBurpXml() {
    const items = findings.map((f) =>
      `  <issue>
    <type>SQL Injection</type>
    <parameter>${f.parameter.replace(/&/g, "&amp;").replace(/</g, "&lt;")}</parameter>
    <technique>${f.type.replace(/&/g, "&amp;").replace(/</g, "&lt;")}</technique>
    <title>${f.title.replace(/&/g, "&amp;").replace(/</g, "&lt;")}</title>
    <payload>${f.payload.replace(/&/g, "&amp;").replace(/</g, "&lt;")}</payload>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <url>${activeTab.config.targetUrl.replace(/&/g, "&amp;").replace(/</g, "&lt;")}</url>
  </issue>`
    ).join("\n");

    const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<issues>\n${items}\n</issues>`;
    const blob = new Blob([xml], { type: "text/xml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sqlmap-findings-${Date.now()}.xml`;
    a.click();
    URL.revokeObjectURL(url);
  }

  // History
  function loadFromHistory(entry: HistoryEntry) {
    const newTab = createTab();
    newTab.config = { ...entry.config, flags: { ...entry.config.flags } };
    newTab.output = entry.output;
    setTabs((prev) => [...prev, newTab]);
    setActiveTabId(newTab.id);
    setShowHistory(false);
  }

  function clearHistory() {
    setHistory([]);
    clearHistoryDb();
  }

  // Export
  function exportReport() {
    const html = exportReportHTML(activeTab);
    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sqlmap-report-${Date.now()}.html`;
    a.click();
    URL.revokeObjectURL(url);
  }

  // Batch
  function startBatch() {
    const urls = batchUrls.split("\n").map((u) => u.trim()).filter(Boolean);
    if (urls.length === 0) return;

    const targets: BatchTarget[] = urls.map((url) => ({ url, status: "pending" }));
    setBatchTargets(targets);

    urls.forEach((url, i) => {
      const newTab = createTab();
      newTab.config = { ...activeTab.config, flags: { ...activeTab.config.flags }, targetUrl: url };
      setTabs((prev) => [...prev, newTab]);

      setTimeout(() => {
        runSqlmap(newTab.id, { ...activeTab.config, flags: { ...activeTab.config.flags }, targetUrl: url });
        setBatchTargets((prev) =>
          prev.map((t, idx) => (idx === i ? { ...t, status: "running" } : t))
        );
      }, i * 500);
    });

    setShowBatch(false);
    setBatchUrls("");
  }

  function getLineClass(line: TerminalLine): string {
    if (line.text === "Initializing sqlmap engine...") return "terminal-line initializing";
    if (line.type === "cmd") return "terminal-line cmd";
    if (line.type === "success") return "terminal-line success";
    if (line.type === "stderr") return "terminal-line error";
    if (line.type === "info" && line.text === "") return "terminal-line";
    if (line.type === "stdout") return classifyLine(line.text);
    return `terminal-line ${line.type}`;
  }

  function highlightSearch(text: string): React.ReactNode {
    if (!searchQuery) return text;
    const idx = text.toLowerCase().indexOf(searchQuery.toLowerCase());
    if (idx === -1) return text;
    return (
      <>
        {text.slice(0, idx)}
        <mark className="search-highlight">{text.slice(idx, idx + searchQuery.length)}</mark>
        {text.slice(idx + searchQuery.length)}
      </>
    );
  }

  const runningCount = tabs.filter((t) => t.isRunning).length;
  const displayOutput = activeTab.viewMode === "requests" ? httpRequests : filteredOutput;

  return (
    <div
      className={`app ${dragOver ? "drag-over" : ""}`}
      onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
      onDragLeave={() => setDragOver(false)}
      onDrop={handleDrop}
    >
      <header className="header">
        <h1>SQLMap UI <span>v2.0</span>{updateAvailable && <span className="update-badge">v{updateAvailable} available</span>}</h1>
        <div className="header-actions">
          <button className="header-btn" onClick={() => setShowHistory(!showHistory)} title="History">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
          </button>
          <button className="header-btn" onClick={() => setShowProfiles(!showProfiles)} title="Profiles">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"/></svg>
          </button>
          <button className="header-btn" onClick={() => setShowImport(!showImport)} title="Import Request">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          </button>
          <button className="header-btn" onClick={() => setShowBatch(!showBatch)} title="Batch Scan">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>
          </button>
          <button
            className="header-btn"
            onClick={exportReport}
            disabled={activeTab.output.length === 0}
            title="Export Report"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
          </button>
          <button className="header-btn" onClick={() => setTheme(theme === "dark" ? "light" : "dark")} title={theme === "dark" ? "Light mode" : "Dark mode"}>
            {theme === "dark" ? (
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
            ) : (
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
            )}
          </button>
        </div>
        <div className="header-status">
          <div className={`status-dot ${runningCount > 0 ? "running" : "ready"}`} />
          {runningCount > 0
            ? `${runningCount} scan${runningCount > 1 ? "s" : ""} running`
            : "Ready"}
        </div>
      </header>

      {/* ── Modal Overlays ── */}
      {showHistory && (
        <div className="modal-overlay" onClick={() => setShowHistory(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Scan History</h2>
              <div style={{ display: "flex", gap: 8 }}>
                {history.length > 0 && (
                  <button className="btn btn-secondary btn-sm" onClick={clearHistory}>Clear All</button>
                )}
                <button className="modal-close" onClick={() => setShowHistory(false)}>x</button>
              </div>
            </div>
            <div className="modal-body">
              {history.length === 0 ? (
                <div className="modal-empty">No scan history yet</div>
              ) : (
                history.map((entry) => (
                  <div key={entry.id} className="history-item" onClick={() => loadFromHistory(entry)}>
                    <div className="history-url">{entry.targetUrl}</div>
                    <div className="history-meta">
                      {new Date(entry.startedAt).toLocaleString()} | Exit: {entry.exitCode ?? "?"}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {showProfiles && (
        <div className="modal-overlay" onClick={() => setShowProfiles(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Profiles</h2>
              <button className="modal-close" onClick={() => setShowProfiles(false)}>x</button>
            </div>
            <div className="modal-body">
              <div className="profile-save">
                <input
                  type="text"
                  placeholder="Profile name..."
                  value={profileName}
                  onChange={(e) => setProfileName(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && saveProfile()}
                />
                <button className="btn btn-primary btn-sm" onClick={saveProfile}>Save Current</button>
              </div>
              {profiles.length === 0 ? (
                <div className="modal-empty">No saved profiles</div>
              ) : (
                profiles.map((p) => (
                  <div key={p.name} className="profile-item">
                    <div className="profile-info" onClick={() => loadProfile(p)}>
                      <div className="profile-name">{p.name}</div>
                      <div className="profile-meta">
                        L{p.config.level}/R{p.config.risk} | T{p.config.threads}
                        {p.config.dbms ? ` | ${p.config.dbms}` : ""}
                      </div>
                    </div>
                    <button className="btn-icon" onClick={() => deleteProfile(p.name)}>x</button>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {showImport && (
        <div className="modal-overlay" onClick={() => setShowImport(false)}>
          <div className="modal modal-lg" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Import Raw Request</h2>
              <button className="modal-close" onClick={() => setShowImport(false)}>x</button>
            </div>
            <div className="modal-body">
              <p className="modal-hint">Paste a raw HTTP request or Burp Suite XML. Supports raw requests from DevTools, .req files, and Burp XML exports:</p>
              <textarea
                className="import-textarea"
                placeholder={`GET /page?id=1 HTTP/1.1\nHost: target.com\nCookie: session=abc123\n\n`}
                value={rawRequest}
                onChange={(e) => setRawRequest(e.target.value)}
                rows={12}
              />
              <button className="btn btn-primary" onClick={applyImport} disabled={!rawRequest.trim()}>
                Apply to Current Tab
              </button>
            </div>
          </div>
        </div>
      )}

      {showBatch && (
        <div className="modal-overlay" onClick={() => setShowBatch(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Batch Scan</h2>
              <button className="modal-close" onClick={() => setShowBatch(false)}>x</button>
            </div>
            <div className="modal-body">
              <p className="modal-hint">One URL per line. Uses current tab config for all targets:</p>
              <textarea
                className="import-textarea"
                placeholder={`https://target1.com/page?id=1\nhttps://target2.com/page?id=1\nhttps://target3.com/page?id=1`}
                value={batchUrls}
                onChange={(e) => setBatchUrls(e.target.value)}
                rows={8}
              />
              <button className="btn btn-primary" onClick={startBatch} disabled={!batchUrls.trim()}>
                Start Batch Scan
              </button>
              {batchTargets.length > 0 && (
                <div className="batch-status">
                  {batchTargets.map((t, i) => (
                    <div key={i} className={`batch-item batch-${t.status}`}>
                      <span className={`batch-dot ${t.status}`} />
                      {t.url}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── Tabs Bar ── */}
      <div className="scan-tabs-bar">
        {tabs.map((tab) => (
          <div
            key={tab.id}
            className={`scan-tab ${tab.id === activeTabId ? "active" : ""} ${tab.isRunning ? "running" : ""}`}
            onClick={() => setActiveTabId(tab.id)}
          >
            {tab.isRunning && <span className="scan-tab-pulse" />}
            <span className="scan-tab-label">{getTabLabel(tab)}</span>
            {tabs.length > 1 && (
              <button className="scan-tab-close" onClick={(e) => { e.stopPropagation(); closeTab(tab.id); }}>
                x
              </button>
            )}
          </div>
        ))}
        <button className="scan-tab-add" onClick={addTab}>+</button>
      </div>

      {/* ── Main Layout ── */}
      <div className="main">
        <aside className="config-panel" style={{ width: panelWidth, minWidth: panelWidth }}>
          <div className="config-section">
            <h2>Target</h2>
            <div className="form-group">
              <label>URL</label>
              <input type="text" placeholder="http://target.com/page?id=1" value={activeTab.config.targetUrl} onChange={(e) => updateConfig("targetUrl", e.target.value)} disabled={activeTab.isRunning} />
            </div>
            <div className="form-group">
              <label>Method</label>
              <select value={activeTab.config.method} onChange={(e) => updateConfig("method", e.target.value)} disabled={activeTab.isRunning}>
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
                <option value="PATCH">PATCH</option>
              </select>
            </div>
            <div className="form-group">
              <label>POST Data</label>
              <input type="text" placeholder="param1=value1&param2=value2" value={activeTab.config.data} onChange={(e) => updateConfig("data", e.target.value)} disabled={activeTab.isRunning} />
            </div>
            <div className="form-group">
              <label>Cookie</label>
              <input type="text" placeholder="PHPSESSID=abc123" value={activeTab.config.cookie} onChange={(e) => updateConfig("cookie", e.target.value)} disabled={activeTab.isRunning} />
            </div>
            <div className="form-group">
              <label>Headers (one per line, use \n)</label>
              <input type="text" placeholder="X-Custom: value\nAuthorization: Bearer ..." value={activeTab.config.headers} onChange={(e) => updateConfig("headers", e.target.value)} disabled={activeTab.isRunning} />
            </div>
          </div>

          <div className="config-section">
            <h2>Detection</h2>
            <div className="form-group">
              <label>Level (1-5)</label>
              <select value={activeTab.config.level} onChange={(e) => updateConfig("level", Number(e.target.value))} disabled={activeTab.isRunning}>
                {[1, 2, 3, 4, 5].map((n) => <option key={n} value={n}>{n}</option>)}
              </select>
            </div>
            <div className="form-group">
              <label>Risk (1-3)</label>
              <select value={activeTab.config.risk} onChange={(e) => updateConfig("risk", Number(e.target.value))} disabled={activeTab.isRunning}>
                {[1, 2, 3].map((n) => <option key={n} value={n}>{n}</option>)}
              </select>
            </div>
            <div className="form-group">
              <label>Threads (1-10)</label>
              <select value={activeTab.config.threads} onChange={(e) => updateConfig("threads", Number(e.target.value))} disabled={activeTab.isRunning}>
                {[1, 2, 3, 4, 5, 6, 7, 8, 9, 10].map((n) => <option key={n} value={n}>{n}</option>)}
              </select>
            </div>
          </div>

          <div className="config-section">
            <h2>Advanced</h2>
            <div className="form-group">
              <label>DBMS</label>
              <select value={activeTab.config.dbms} onChange={(e) => updateConfig("dbms", e.target.value)} disabled={activeTab.isRunning}>
                <option value="">Auto-detect</option>
                <option value="MySQL">MySQL</option>
                <option value="PostgreSQL">PostgreSQL</option>
                <option value="Oracle">Oracle</option>
                <option value="Microsoft SQL Server">MSSQL</option>
                <option value="SQLite">SQLite</option>
                <option value="MariaDB">MariaDB</option>
              </select>
            </div>
            <div className="form-group">
              <label>Technique (BEUSTQ)</label>
              <input type="text" placeholder="BEUSTQ (all)" value={activeTab.config.technique} onChange={(e) => updateConfig("technique", e.target.value)} disabled={activeTab.isRunning} />
            </div>
            <div className="form-group">
              <label>Tamper Script</label>
              <input type="text" placeholder="space2comment,charencode" value={activeTab.config.tamper} onChange={(e) => updateConfig("tamper", e.target.value)} disabled={activeTab.isRunning} />
            </div>
          </div>

          <div className="config-section">
            <h2>Options</h2>
            <div className="checkbox-group">
              {([
                ["batch", "Batch (no prompts)"], ["randomAgent", "Random Agent"],
                ["forms", "Parse Forms"], ["dbs", "List DBs"],
                ["tables", "List Tables"], ["dump", "Dump Data"],
                ["currentDb", "Current DB"], ["currentUser", "Current User"],
                ["passwords", "Passwords"], ["tor", "Use Tor"],
              ] as const).map(([key, label]) => (
                <label key={key} className="checkbox-item">
                  <input type="checkbox" checked={activeTab.config.flags[key]} onChange={() => toggleFlag(key)} disabled={activeTab.isRunning} />
                  {label}
                </label>
              ))}
            </div>
          </div>

          <div className="config-section">
            <h2>Extra Arguments</h2>
            <div className="form-group">
              <textarea placeholder="--proxy http://127.0.0.1:8080 --os-shell" value={activeTab.config.extraArgs} onChange={(e) => updateConfig("extraArgs", e.target.value)} disabled={activeTab.isRunning} />
            </div>
          </div>

          <div className="actions">
            {activeTab.isRunning ? (
              <button className="btn btn-danger" onClick={stopSqlmap}>Stop</button>
            ) : (
              <button className="btn btn-primary" onClick={() => runSqlmap()} disabled={!activeTab.config.targetUrl.trim()}>Run SQLMap</button>
            )}
            <button className="btn btn-secondary" onClick={clearOutput}>Clear</button>
          </div>
        </aside>

        {/* Resize handle */}
        <div className="resize-handle" onMouseDown={startResize} />

        <div className="terminal-panel">
          <div className="terminal-header">
            <div className="terminal-tabs">
              <button className={`terminal-tab ${activeTab.viewMode === "output" ? "active" : ""}`} onClick={() => setViewMode("output")}>
                Output
              </button>
              <button className={`terminal-tab ${activeTab.viewMode === "command" ? "active" : ""}`} onClick={() => setViewMode("command")}>
                Command
              </button>
              <button className={`terminal-tab ${activeTab.viewMode === "requests" ? "active" : ""}`} onClick={() => setViewMode("requests")}>
                Requests ({httpRequests.length})
              </button>
              <button className={`terminal-tab ${activeTab.viewMode === "findings" ? "active" : ""} ${findings.length > 0 ? "has-findings" : ""}`} onClick={() => setViewMode("findings")}>
                Findings ({findings.length})
              </button>
            </div>
            <div className="terminal-meta">
              <span>{activeTab.viewMode === "output" ? (searchQuery ? `${filteredOutput.length}/` : "") + `${activeTab.output.length} lines` : ""}</span>
              <button className={`search-toggle ${searchOpen ? "active" : ""}`} onClick={() => { setSearchOpen(!searchOpen); setTimeout(() => searchInputRef.current?.focus(), 50); }}>
                Search
              </button>
            </div>
          </div>

          {searchOpen && (
            <div className="search-bar">
              <input
                ref={searchInputRef}
                type="text"
                placeholder="Search output..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="search-input"
              />
              {searchQuery && (
                <span className="search-count">{filteredOutput.length} matches</span>
              )}
              <button className="search-close" onClick={() => { setSearchOpen(false); setSearchQuery(""); }}>x</button>
            </div>
          )}

          <div className="terminal-body" ref={terminalRef}>
            {activeTab.viewMode === "findings" ? (
              findings.length === 0 ? (
                <div className="terminal-empty">No vulnerabilities found yet. Run a scan to detect SQL injections.</div>
              ) : (
                <div className="findings-list">
                  <div className="findings-toolbar">
                    <span className="findings-count">{findings.length} finding{findings.length !== 1 ? "s" : ""}</span>
                    <button className="btn btn-secondary btn-sm" onClick={exportBurpXml}>Export XML</button>
                  </div>
                  {findings.map((f, i) => (
                    <div key={i} className={`finding-card ${f.type === "DBMS Detected" ? "finding-info" : "finding-vuln"}`}>
                      <div className="finding-header">
                        <span className="finding-badge">{f.type === "DBMS Detected" ? "INFO" : "VULN"}</span>
                        <span className="finding-param">{f.parameter}</span>
                      </div>
                      <div className="finding-type">{f.type}</div>
                      {f.title && <div className="finding-title">{f.title}</div>}
                      {f.payload && <div className="finding-payload"><code>{f.payload}</code></div>}
                    </div>
                  ))}
                </div>
              )
            ) : activeTab.viewMode === "command" ? (
              <div className="terminal-line cmd">{getCommandString()}</div>
            ) : displayOutput.length === 0 ? (
              <div className="terminal-empty">
                {activeTab.viewMode === "requests"
                  ? "No HTTP requests captured. Use -v 4 or higher in extra arguments to see requests."
                  : searchQuery
                    ? "No matches found"
                    : 'Configure target and click "Run SQLMap" to start'}
              </div>
            ) : (
              displayOutput.map((line, i) => (
                <div key={i} className={getLineClass(line)}>
                  {highlightSearch(line.text)}
                </div>
              ))
            )}
          </div>
          {activeTab.isRunning && (
            <form className="stdin-bar" onSubmit={(e) => {
              e.preventDefault();
              const input = (e.target as HTMLFormElement).elements.namedItem("stdinInput") as HTMLInputElement;
              const value = input.value;
              if (!value && value !== "") return;
              const child = childRefs.current.get(activeTabId);
              if (child) {
                child.write(value + "\n");
                updateTab(activeTabId, (t) => ({
                  ...t,
                  output: [...t.output, { text: `> ${value}`, type: "cmd" }],
                }));
              }
              input.value = "";
            }}>
              <span className="stdin-prompt">&gt;</span>
              <input name="stdinInput" type="text" className="stdin-input" placeholder="Type response to sqlmap prompt..." autoFocus />
              <button type="submit" className="stdin-send">Send</button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
