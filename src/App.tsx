import { useState, useRef, useEffect, useCallback } from "react";
import { Command } from "@tauri-apps/plugin-shell";

interface TerminalLine {
  text: string;
  type: "stdout" | "stderr" | "info" | "cmd" | "success";
}

interface SqlmapConfig {
  targetUrl: string;
  data: string;
  cookie: string;
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
  viewMode: "output" | "command";
}

type ChildProcess = Awaited<ReturnType<Command<string>["spawn"]>>;

const DEFAULT_CONFIG: SqlmapConfig = {
  targetUrl: "",
  data: "",
  cookie: "",
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

export default function App() {
  const [tabs, setTabs] = useState<ScanTab[]>(() => [createTab()]);
  const [activeTabId, setActiveTabId] = useState<string>("tab-1");
  const terminalRef = useRef<HTMLDivElement>(null);
  const childRefs = useRef<Map<string, ChildProcess>>(new Map());

  const activeTab = tabs.find((t) => t.id === activeTabId) ?? tabs[0];

  const scrollToBottom = useCallback(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [activeTab?.output, scrollToBottom]);

  function updateTab(tabId: string, updater: (tab: ScanTab) => ScanTab) {
    setTabs((prev) => prev.map((t) => (t.id === tabId ? updater(t) : t)));
  }

  function updateConfig<K extends keyof SqlmapConfig>(
    key: K,
    value: SqlmapConfig[K]
  ) {
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
    const args: string[] = [];

    if (config.targetUrl) args.push("-u", config.targetUrl);
    if (config.data) args.push("--data", config.data);
    if (config.cookie) args.push("--cookie", config.cookie);
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

  async function runSqlmap() {
    const tabId = activeTabId;
    const tab = tabs.find((t) => t.id === tabId);
    if (!tab || !tab.config.targetUrl.trim()) return;

    const args = buildArgs(tab.config);

    updateTab(tabId, (t) => ({
      ...t,
      isRunning: true,
      initializing: true,
      viewMode: "output",
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
          return {
            ...t,
            initializing: false,
            output: [...output, { text: line, type: "stdout" }],
          };
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
        updateTab(tabId, (t) => ({
          ...t,
          isRunning: false,
          output: [
            ...t.output,
            { text: "", type: "info" },
            {
              text: `Process exited with code ${exitCode}`,
              type: exitCode === 0 ? "success" : "stderr",
            },
          ],
        }));
        childRefs.current.delete(tabId);
      });

      command.on("error", (error: string) => {
        updateTab(tabId, (t) => ({
          ...t,
          isRunning: false,
          output: [
            ...t.output,
            { text: `Error: ${error}`, type: "stderr" },
          ],
        }));
        childRefs.current.delete(tabId);
      });

      const child = await command.spawn();
      childRefs.current.set(tabId, child);
    } catch (err) {
      updateTab(tabId, (t) => ({
        ...t,
        isRunning: false,
        output: [
          ...t.output,
          { text: `Failed to start: ${err}`, type: "stderr" },
        ],
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
        output: [
          ...t.output,
          { text: "", type: "info" },
          { text: "Process killed by user", type: "stderr" },
        ],
      }));
    }
  }

  function clearOutput() {
    updateTab(activeTabId, (t) => ({ ...t, output: [] }));
  }

  function setViewMode(mode: "output" | "command") {
    updateTab(activeTabId, (t) => ({ ...t, viewMode: mode }));
  }

  function getLineClass(type: TerminalLine["type"]): string {
    switch (type) {
      case "stderr":
        return "terminal-line error";
      case "info":
        return "terminal-line info";
      case "cmd":
        return "terminal-line cmd";
      case "success":
        return "terminal-line success";
      default:
        return "terminal-line";
    }
  }

  const runningCount = tabs.filter((t) => t.isRunning).length;

  return (
    <div className="app">
      <header className="header">
        <h1>
          SQLMap UI <span>v1.0</span>
        </h1>
        <div className="header-status">
          <div
            className={`status-dot ${runningCount > 0 ? "running" : "ready"}`}
          />
          {runningCount > 0
            ? `${runningCount} scan${runningCount > 1 ? "s" : ""} running`
            : "Ready"}
        </div>
      </header>

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
              <button
                className="scan-tab-close"
                onClick={(e) => {
                  e.stopPropagation();
                  closeTab(tab.id);
                }}
              >
                x
              </button>
            )}
          </div>
        ))}
        <button className="scan-tab-add" onClick={addTab}>
          +
        </button>
      </div>

      <div className="main">
        <aside className="config-panel">
          <div className="config-section">
            <h2>Target</h2>
            <div className="form-group">
              <label>URL</label>
              <input
                type="text"
                placeholder="http://target.com/page?id=1"
                value={activeTab.config.targetUrl}
                onChange={(e) => updateConfig("targetUrl", e.target.value)}
                disabled={activeTab.isRunning}
              />
            </div>
            <div className="form-group">
              <label>POST Data</label>
              <input
                type="text"
                placeholder="param1=value1&param2=value2"
                value={activeTab.config.data}
                onChange={(e) => updateConfig("data", e.target.value)}
                disabled={activeTab.isRunning}
              />
            </div>
            <div className="form-group">
              <label>Cookie</label>
              <input
                type="text"
                placeholder="PHPSESSID=abc123"
                value={activeTab.config.cookie}
                onChange={(e) => updateConfig("cookie", e.target.value)}
                disabled={activeTab.isRunning}
              />
            </div>
          </div>

          <div className="config-section">
            <h2>Detection</h2>
            <div className="form-group">
              <label>Level (1-5)</label>
              <select
                value={activeTab.config.level}
                onChange={(e) => updateConfig("level", Number(e.target.value))}
                disabled={activeTab.isRunning}
              >
                {[1, 2, 3, 4, 5].map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </select>
            </div>
            <div className="form-group">
              <label>Risk (1-3)</label>
              <select
                value={activeTab.config.risk}
                onChange={(e) => updateConfig("risk", Number(e.target.value))}
                disabled={activeTab.isRunning}
              >
                {[1, 2, 3].map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </select>
            </div>
            <div className="form-group">
              <label>Threads (1-10)</label>
              <select
                value={activeTab.config.threads}
                onChange={(e) =>
                  updateConfig("threads", Number(e.target.value))
                }
                disabled={activeTab.isRunning}
              >
                {[1, 2, 3, 4, 5, 6, 7, 8, 9, 10].map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="config-section">
            <h2>Advanced</h2>
            <div className="form-group">
              <label>DBMS</label>
              <select
                value={activeTab.config.dbms}
                onChange={(e) => updateConfig("dbms", e.target.value)}
                disabled={activeTab.isRunning}
              >
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
              <input
                type="text"
                placeholder="BEUSTQ (all)"
                value={activeTab.config.technique}
                onChange={(e) => updateConfig("technique", e.target.value)}
                disabled={activeTab.isRunning}
              />
            </div>
            <div className="form-group">
              <label>Tamper Script</label>
              <input
                type="text"
                placeholder="space2comment,charencode"
                value={activeTab.config.tamper}
                onChange={(e) => updateConfig("tamper", e.target.value)}
                disabled={activeTab.isRunning}
              />
            </div>
          </div>

          <div className="config-section">
            <h2>Options</h2>
            <div className="checkbox-group">
              {(
                [
                  ["batch", "Batch (no prompts)"],
                  ["randomAgent", "Random Agent"],
                  ["forms", "Parse Forms"],
                  ["dbs", "List DBs"],
                  ["tables", "List Tables"],
                  ["dump", "Dump Data"],
                  ["currentDb", "Current DB"],
                  ["currentUser", "Current User"],
                  ["passwords", "Passwords"],
                  ["tor", "Use Tor"],
                ] as const
              ).map(([key, label]) => (
                <label key={key} className="checkbox-item">
                  <input
                    type="checkbox"
                    checked={activeTab.config.flags[key]}
                    onChange={() => toggleFlag(key)}
                    disabled={activeTab.isRunning}
                  />
                  {label}
                </label>
              ))}
            </div>
          </div>

          <div className="config-section">
            <h2>Extra Arguments</h2>
            <div className="form-group">
              <textarea
                placeholder="--proxy http://127.0.0.1:8080 --os-shell"
                value={activeTab.config.extraArgs}
                onChange={(e) => updateConfig("extraArgs", e.target.value)}
                disabled={activeTab.isRunning}
              />
            </div>
          </div>

          <div className="actions">
            {activeTab.isRunning ? (
              <button className="btn btn-danger" onClick={stopSqlmap}>
                Stop
              </button>
            ) : (
              <button
                className="btn btn-primary"
                onClick={runSqlmap}
                disabled={!activeTab.config.targetUrl.trim()}
              >
                Run SQLMap
              </button>
            )}
            <button className="btn btn-secondary" onClick={clearOutput}>
              Clear
            </button>
          </div>
        </aside>

        <div className="terminal-panel">
          <div className="terminal-header">
            <div className="terminal-tabs">
              <button
                className={`terminal-tab ${activeTab.viewMode === "output" ? "active" : ""}`}
                onClick={() => setViewMode("output")}
              >
                Output
              </button>
              <button
                className={`terminal-tab ${activeTab.viewMode === "command" ? "active" : ""}`}
                onClick={() => setViewMode("command")}
              >
                Command Preview
              </button>
            </div>
            <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>
              {activeTab.output.length} lines
            </span>
          </div>
          <div className="terminal-body" ref={terminalRef}>
            {activeTab.viewMode === "command" ? (
              <div className="terminal-line cmd">{getCommandString()}</div>
            ) : activeTab.output.length === 0 ? (
              <div className="terminal-empty">
                Configure target and click "Run SQLMap" to start
              </div>
            ) : (
              activeTab.output.map((line, i) => (
                <div
                  key={i}
                  className={
                    line.text === "Initializing sqlmap engine..."
                      ? "terminal-line initializing"
                      : getLineClass(line.type)
                  }
                >
                  {line.text}
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
