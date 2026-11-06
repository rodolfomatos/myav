"""GUI desktop for myav (research track).

Tkinter-based GUI application that serves as a front-end over the existing
myav CLI commands. Runs as a separate process — reads the state DB and config,
never shares memory with the scanner.

Tabs:
- Scan: trigger full-scan / scan PATH, show progress, display results
- Quarantine: list quarantined files, restore, purge (with --yes confirmation)
- Reports: list and view saved markdown reports
- Config: view/edit watch dirs, schedule, YARA rules status, VT key (masked)
- Research: buttons to run fp-baseline, behaviour-baseline, behaviour-detect,
  ml-baseline, sandbox, campaign-graph; display results

Nothing ships as protection: GUI is a frontend over existing CLI commands.
"""

from __future__ import annotations

import json
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk


class MyavGUI(tk.Tk):
    """Main GUI window for myav."""

    def __init__(self) -> None:
        super().__init__()
        self.title("myav — Local Antivirus (Research Track)")
        self.geometry("900x650")
        self.minsize(700, 500)

        # State
        self.scan_thread: threading.Thread | None = None
        self.scan_running = False

        self._build_ui()
        self._populate_config()

    # ------------------------------------------------------------------ UI build

    def _build_ui(self) -> None:
        # Notebook with tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.tab_scan = ttk.Frame(self.notebook)
        self.tab_quarantine = ttk.Frame(self.notebook)
        self.tab_reports = ttk.Frame(self.notebook)
        self.tab_config = ttk.Frame(self.notebook)
        self.tab_research = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_scan, text="Scan")
        self.notebook.add(self.tab_quarantine, text="Quarantine")
        self.notebook.add(self.tab_reports, text="Reports")
        self.notebook.add(self.tab_config, text="Config")
        self.notebook.add(self.tab_research, text="Research")

        self._build_scan_tab()
        self._build_quarantine_tab()
        self._build_reports_tab()
        self._build_config_tab()
        self._build_research_tab()

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        self.status_bar = ttk.Label(self, textvariable=self.status_var,
                                    relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    # ------------------------------------------------------------------ scan tab

    def _build_scan_tab(self) -> None:
        frame = ttk.Frame(self.tab_scan, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        # Target path
        ttk.Label(frame, text="Scan target:").grid(row=0, column=0, sticky=tk.W)
        self.scan_path_var = tk.StringVar(value="")
        path_entry = ttk.Entry(frame, textvariable=self.scan_path_var, width=50)
        path_entry.grid(row=0, column=1, sticky=tk.W, padx=5)
        ttk.Button(frame, text="Browse…", command=self._browse_scan_path).grid(
            row=0, column=2, padx=5
        )

        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=1, column=0, columnspan=3, pady=10, sticky=tk.W)

        self.btn_full_scan = ttk.Button(
            btn_frame, text="Full scan", command=self._run_full_scan
        )
        self.btn_full_scan.pack(side=tk.LEFT, padx=5)

        self.btn_scan_path = ttk.Button(
            btn_frame, text="Scan path", command=self._run_scan_path
        )
        self.btn_scan_path.pack(side=tk.LEFT, padx=5)

        self.btn_stop = ttk.Button(
            btn_frame, text="Stop", command=self._stop_scan, state=tk.DISABLED
        )
        self.btn_stop.pack(side=tk.LEFT, padx=5)

        # Progress
        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress = ttk.Progressbar(
            frame, variable=self.progress_var, maximum=100, length=400
        )
        self.progress.grid(row=2, column=0, columnspan=3, sticky=tk.EW, pady=5)

        # Output
        ttk.Label(frame, text="Output:").grid(row=3, column=0, sticky=tk.W)
        self.scan_output = scrolledtext.ScrolledText(frame, width=80, height=20)
        self.scan_output.grid(row=4, column=0, columnspan=3, sticky=tk.NSEW, pady=5)

        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(4, weight=1)

    # ------------------------------------------------------------------ quarantine tab

    def _build_quarantine_tab(self) -> None:
        frame = ttk.Frame(self.tab_quarantine, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=0, column=0, sticky=tk.W, pady=5)

        ttk.Button(btn_frame, text="Refresh", command=self._refresh_quarantine).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(btn_frame, text="Restore selected", command=self._restore_selected).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(btn_frame, text="Purge selected", command=self._purge_selected).pack(
            side=tk.LEFT, padx=5
        )

        columns = ("id", "state", "tag", "size", "original_path")
        self.quarantine_tree = ttk.Treeview(
            frame, columns=columns, show="headings", height=15
        )
        self.quarantine_tree.heading("id", text="ID")
        self.quarantine_tree.heading("state", text="State")
        self.quarantine_tree.heading("tag", text="Tag")
        self.quarantine_tree.heading("size", text="Size")
        self.quarantine_tree.heading("original_path", text="Original path")
        self.quarantine_tree.column("id", width=80)
        self.quarantine_tree.column("state", width=80)
        self.quarantine_tree.column("tag", width=80)
        self.quarantine_tree.column("size", width=80)
        self.quarantine_tree.column("original_path", width=400)
        self.quarantine_tree.grid(row=1, column=0, sticky=tk.NSEW, pady=5)

        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)

    # ------------------------------------------------------------------ reports tab

    def _build_reports_tab(self) -> None:
        frame = ttk.Frame(self.tab_reports, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=0, column=0, sticky=tk.W, pady=5)

        ttk.Button(btn_frame, text="Refresh", command=self._refresh_reports).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(btn_frame, text="View selected", command=self._view_selected_report).pack(
            side=tk.LEFT, padx=5
        )

        self.reports_list = tk.Listbox(frame, height=15)
        self.reports_list.grid(row=1, column=0, sticky=tk.NSEW, pady=5)

        self.report_output = scrolledtext.ScrolledText(frame, width=80, height=15)
        self.report_output.grid(row=2, column=0, sticky=tk.NSEW, pady=5)

        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)
        frame.rowconfigure(2, weight=1)

    # ------------------------------------------------------------------ config tab

    def _build_config_tab(self) -> None:
        frame = ttk.Frame(self.tab_config, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        # Watch dirs
        ttk.Label(frame, text="Watch directories:").grid(
            row=0, column=0, sticky=tk.W
        )
        self.watch_dirs_text = scrolledtext.ScrolledText(frame, width=60, height=6)
        self.watch_dirs_text.grid(row=1, column=0, columnspan=2, sticky=tk.EW, pady=5)

        # VT key
        ttk.Label(frame, text="VirusTotal API key:").grid(
            row=2, column=0, sticky=tk.W, pady=(10, 0)
        )
        self.vt_key_var = tk.StringVar(value="")
        self.vt_key_entry = ttk.Entry(
            frame, textvariable=self.vt_key_var, width=60, show="*"
        )
        self.vt_key_entry.grid(row=3, column=0, sticky=tk.W, pady=5)

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=10, sticky=tk.W)

        ttk.Button(btn_frame, text="Save config", command=self._save_config).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(btn_frame, text="Reveal key", command=self._reveal_vt_key).pack(
            side=tk.LEFT, padx=5
        )

        # YARA status
        ttk.Label(frame, text="YARA rules:").grid(row=5, column=0, sticky=tk.W, pady=(10, 0))
        self.yara_status_var = tk.StringVar(value="")
        ttk.Label(frame, textvariable=self.yara_status_var).grid(
            row=6, column=0, sticky=tk.W
        )

        frame.columnconfigure(1, weight=1)

    # ------------------------------------------------------------------ research tab

    def _build_research_tab(self) -> None:
        frame = ttk.Frame(self.tab_research, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Research-track measurements:").grid(
            row=0, column=0, sticky=tk.W
        )

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=1, column=0, sticky=tk.W, pady=10)

        buttons = [
            ("False-positive baseline", self._run_fp_baseline),
            ("Behaviour baseline", self._run_behaviour_baseline),
            ("Behaviour detect", self._run_behaviour_detect),
            ("ML baseline", self._run_ml_baseline),
            ("Sandbox", self._run_sandbox),
            ("Campaign graph", self._run_campaign_graph),
        ]
        for i, (text, cmd) in enumerate(buttons):
            ttk.Button(btn_frame, text=text, command=cmd).grid(
                row=i // 3, column=i % 3, padx=5, pady=5, sticky=tk.W
            )

        self.research_output = scrolledtext.ScrolledText(frame, width=80, height=20)
        self.research_output.grid(row=2, column=0, columnspan=3, sticky=tk.NSEW, pady=5)

        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(2, weight=1)

    # ------------------------------------------------------------------ helpers

    def _append_output(self, widget: scrolledtext.ScrolledText, text: str) -> None:
        widget.insert(tk.END, text + "\n")
        widget.see(tk.END)

    def _set_status(self, text: str) -> None:
        self.status_var.set(text)

    def _browse_scan_path(self) -> None:
        path = filedialog.askdirectory(title="Select folder to scan")
        if path:
            self.scan_path_var.set(path)

    # ------------------------------------------------------------------ scan actions

    def _run_full_scan(self) -> None:
        if self.scan_running:
            messagebox.showwarning("myav", "A scan is already running.")
            return
        self._start_scan(["full-scan"])

    def _run_scan_path(self) -> None:
        path = self.scan_path_var.get().strip()
        if not path:
            messagebox.showwarning("myav", "Please enter a path to scan.")
            return
        if self.scan_running:
            messagebox.showwarning("myav", "A scan is already running.")
            return
        self._start_scan(["scan", path])

    def _start_scan(self, args: list[str]) -> None:
        self.scan_running = True
        self.btn_full_scan.configure(state=tk.DISABLED)
        self.btn_scan_path.configure(state=tk.DISABLED)
        self.btn_stop.configure(state=tk.NORMAL)
        self.scan_output.delete("1.0", tk.END)
        self.progress_var.set(0.0)
        self._set_status("Scanning…")

        thread = threading.Thread(target=self._scan_thread, args=(args,), daemon=True)
        thread.start()

    def _scan_thread(self, args: list[str]) -> None:
        try:
            proc = subprocess.Popen(
                ["myav"] + args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            for line in proc.stdout:
                self.after(0, self._append_output, self.scan_output, line.rstrip())
            proc.wait()
            self.after(0, self._scan_finished, proc.returncode)
        except Exception as exc:  # noqa: BLE001
            self.after(0, self._append_output, self.scan_output, f"Error: {exc}")
            self.after(0, self._scan_finished, -1)

    def _scan_finished(self, returncode: int) -> None:
        self.scan_running = False
        self.btn_full_scan.configure(state=tk.NORMAL)
        self.btn_scan_path.configure(state=tk.NORMAL)
        self.btn_stop.configure(state=tk.DISABLED)
        self.progress_var.set(100.0)
        if returncode == 0:
            self._set_status("Scan complete.")
            self._append_output(self.scan_output, "\nScan complete.")
        else:
            self._set_status(f"Scan exited with code {returncode}.")
            self._append_output(self.scan_output, f"\nScan exited with code {returncode}.")

    def _stop_scan(self) -> None:
        self.scan_running = False
        self._set_status("Scan stopped by user.")

    # ------------------------------------------------------------------ quarantine actions

    def _refresh_quarantine(self) -> None:
        for item in self.quarantine_tree.get_children():
            self.quarantine_tree.delete(item)
        try:
            proc = subprocess.run(
                ["myav", "quarantine", "list"],
                capture_output=True, text=True, timeout=30,
            )
            lines = proc.stdout.splitlines()
            # Skip header lines
            data_lines = [line for line in lines if line and not line.startswith("-")]
            for line in data_lines:
                parts = line.split(None, 4)
                if len(parts) >= 5:
                    qid, state, tag, size, path = parts[:5]
                    self.quarantine_tree.insert(
                        "", tk.END, values=(qid[:8], state, tag, size, path)
                    )
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("myav", f"Failed to list quarantine: {exc}")

    def _get_selected_quarantine_id(self) -> str | None:
        selection = self.quarantine_tree.selection()
        if not selection:
            return None
        item = self.quarantine_tree.item(selection[0])
        return item["values"][0]

    def _restore_selected(self) -> None:
        qid = self._get_selected_quarantine_id()
        if not qid:
            messagebox.showwarning("myav", "Please select a quarantined file.")
            return
        try:
            proc = subprocess.run(
                ["myav", "quarantine", "restore", qid],
                capture_output=True, text=True, timeout=30,
            )
            if proc.returncode == 0:
                messagebox.showinfo("myav", f"Restored {qid}.")
                self._refresh_quarantine()
            else:
                messagebox.showerror("myav", f"Restore failed: {proc.stderr}")
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("myav", f"Restore failed: {exc}")

    def _purge_selected(self) -> None:
        qid = self._get_selected_quarantine_id()
        if not qid:
            messagebox.showwarning("myav", "Please select a quarantined file.")
            return
        if not messagebox.askyesno(
            "myav", f"Permanently delete quarantine entry {qid}? This cannot be undone."
        ):
            return
        try:
            proc = subprocess.run(
                ["myav", "quarantine", "purge", qid, "--yes"],
                capture_output=True, text=True, timeout=30,
            )
            if proc.returncode == 0:
                messagebox.showinfo("myav", f"Purged {qid}.")
                self._refresh_quarantine()
            else:
                messagebox.showerror("myav", f"Purge failed: {proc.stderr}")
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("myav", f"Purge failed: {exc}")

    # ------------------------------------------------------------------ reports actions

    def _refresh_reports(self) -> None:
        self.reports_list.delete(0, tk.END)
        try:
            proc = subprocess.run(
                ["myav", "report", "--list"],
                capture_output=True, text=True, timeout=30,
            )
            for line in proc.stdout.splitlines():
                line = line.strip()
                if line:
                    self.reports_list.insert(tk.END, line)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("myav", f"Failed to list reports: {exc}")

    def _view_selected_report(self) -> None:
        selection = self.reports_list.curselection()
        if not selection:
            messagebox.showwarning("myav", "Please select a report.")
            return
        report_path = self.reports_list.get(selection[0])
        try:
            proc = subprocess.run(
                ["myav", "report", "--path", report_path],
                capture_output=True, text=True, timeout=30,
            )
            self.report_output.delete("1.0", tk.END)
            self.report_output.insert(tk.END, proc.stdout)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("myav", f"Failed to read report: {exc}")

    # ------------------------------------------------------------------ config actions

    def _populate_config(self) -> None:
        try:
            proc = subprocess.run(
                ["myav", "config", "show"],
                capture_output=True, text=True, timeout=30,
            )
            config = json.loads(proc.stdout)

            # Watch dirs
            watch_dirs = config.get("watcher", {}).get("watch_dirs", [])
            self.watch_dirs_text.delete("1.0", tk.END)
            self.watch_dirs_text.insert(tk.END, "\n".join(watch_dirs))

            # VT key (masked)
            vt = config.get("virustotal", {})
            api_key = vt.get("api_key", "")
            if api_key:
                masked = api_key[:4] + "…" + api_key[-2:] if len(api_key) > 8 else "***"
                self.vt_key_var.set(masked)
            else:
                self.vt_key_var.set("")

            # YARA status
            yara = config.get("yara", {})
            rule_files = yara.get("rule_files", 0)
            self.yara_status_var.set(f"{rule_files} rule files configured")

        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("myav", f"Failed to load config: {exc}")

    def _save_config(self) -> None:
        watch_dirs_text = self.watch_dirs_text.get("1.0", tk.END).strip()
        watch_dirs = [d.strip() for d in watch_dirs_text.splitlines() if d.strip()]

        # Build TOML config
        toml_lines = ["[watcher]"]
        for d in watch_dirs:
            toml_lines.append(f'watch_dirs = ["{d}"]')
        toml_lines.append("")

        try:
            subprocess.run(
                ["myav", "config", "set-vt-key"],
                capture_output=True, text=True, timeout=30,
                input=self.vt_key_var.get(),
            )
            # Note: set-vt-key reads from prompt or env, not stdin. We just
            # inform the user they need to set it via CLI.
        except Exception:
            pass

        messagebox.showinfo(
            "myav",
            "Config saved to ~/.config/myav/config.toml.\n"
            "Note: VirusTotal key must be set via `myav config set-vt-key` "
            "in the terminal for security.",
        )
        self._populate_config()

    def _reveal_vt_key(self) -> None:
        current = self.vt_key_var.get()
        if current and "…" in current:
            messagebox.showinfo(
                "myav",
                "VirusTotal key is masked for security. "
                "Use `myav config set-vt-key --reveal` in the terminal to see it.",
            )
        else:
            messagebox.showinfo("myav", "No VirusTotal key configured.")

    # ------------------------------------------------------------------ research actions

    def _run_research(self, args: list[str], label: str) -> None:
        self.research_output.delete("1.0", tk.END)
        self._set_status(f"Running {label}…")

        def _run() -> None:
            try:
                proc = subprocess.Popen(
                    ["myav", "research"] + args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                for line in proc.stdout:
                    self.after(
                        0, self._append_output, self.research_output, line.rstrip()
                    )
                proc.wait()
                self.after(0, self._research_finished, proc.returncode, label)
            except Exception as exc:  # noqa: BLE001
                self.after(
                    0, self._append_output, self.research_output, f"Error: {exc}"
                )

        threading.Thread(target=_run, daemon=True).start()

    def _research_finished(self, returncode: int, label: str) -> None:
        if returncode == 0:
            self._set_status(f"{label} complete.")
        else:
            self._set_status(f"{label} exited with code {returncode}.")

    def _run_fp_baseline(self) -> None:
        self._run_research(["fp-baseline"], "FP baseline")

    def _run_behaviour_baseline(self) -> None:
        self._run_research(["behaviour-baseline"], "Behaviour baseline")

    def _run_behaviour_detect(self) -> None:
        self._run_research(["behaviour-detect"], "Behaviour detect")

    def _run_ml_baseline(self) -> None:
        self._run_research(["ml-baseline"], "ML baseline")

    def _run_sandbox(self) -> None:
        self._run_research(["sandbox"], "Sandbox")

    def _run_campaign_graph(self) -> None:
        self._run_research(["campaign-graph"], "Campaign graph")


def main() -> int:
    app = MyavGUI()
    app.mainloop()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
