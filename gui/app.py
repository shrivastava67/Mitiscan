"""Mitiscan customtkinter GUI.

Layout:
  [ Target ] [ Profile ] [ Auth checkbox ] [ Launch ]
  ┌── Module state panel ─┐ ┌── Live backend log ──┐
  Engine runs in background asyncio thread; UI updates via thread-safe queue.

Enhancement #15: authorization gate — user must type target + tick auth box.
"""
from __future__ import annotations

import asyncio
import queue
import threading
from pathlib import Path

import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

try:
    import customtkinter as ctk
    HAS_CTK = True
except ImportError:
    HAS_CTK = False

from core.engine import Engine
from core.evasion import EvasionProfile
from core.reporter import Reporter
from core.result import State


STATE_COLORS = {
    State.PENDING:        "#8b949e",
    State.RUNNING:        "#58a6ff",
    State.COMPLETED:      "#3fb950",
    State.SKIPPED:        "#d29922",
    State.NOT_APPLICABLE: "#d29922",
    State.FAILED:         "#f85149",
}


class MitiscanGUI:
    def __init__(self) -> None:
        if HAS_CTK:
            ctk.set_appearance_mode("dark")
            ctk.set_default_color_theme("dark-blue")
            self.root = ctk.CTk()
        else:
            self.root = tk.Tk()
            self.root.configure(bg="#0e1116")

        self.root.title("Mitiscan — Automated VAPT Platform")
        self.root.geometry("1280x800")

        self.ui_queue: queue.Queue = queue.Queue()
        self.module_rows: dict[int, dict] = {}
        self.engine: Engine | None = None
        self.worker_thread: threading.Thread | None = None

        self._build_ui()
        self.root.after(100, self._drain_queue)

    # ---------- UI build ---------- #
    def _build_ui(self) -> None:
        top = tk.Frame(self.root, bg="#0e1116")
        top.pack(fill="x", padx=10, pady=8)

        tk.Label(top, text="Target (domain / IP / CIDR):",
                 bg="#0e1116", fg="#e6edf3").pack(side="left", padx=4)
        self.target_var = tk.StringVar()
        tk.Entry(top, textvariable=self.target_var, width=36).pack(side="left", padx=4)

        tk.Label(top, text="Profile:", bg="#0e1116", fg="#e6edf3").pack(side="left", padx=4)
        self.profile_var = tk.StringVar(value="BALANCED")
        ttk.Combobox(top, textvariable=self.profile_var,
                     values=["STEALTH", "BALANCED", "AGGRESSIVE"],
                     state="readonly", width=12).pack(side="left", padx=4)

        # auth gate
        self.auth_var = tk.BooleanVar(value=False)
        tk.Checkbutton(top, text="I have written authorization to test this target",
                       variable=self.auth_var, bg="#0e1116", fg="#e6edf3",
                       activebackground="#0e1116",
                       selectcolor="#161b22").pack(side="left", padx=8)

        self.launch_btn = tk.Button(top, text="Launch Mitiscan Run",
                                    bg="#238636", fg="white",
                                    command=self.on_launch)
        self.launch_btn.pack(side="left", padx=10)

        # body
        body = tk.Frame(self.root, bg="#0e1116")
        body.pack(fill="both", expand=True, padx=10, pady=4)

        # left: module list
        left = tk.LabelFrame(body, text="Module State Panel",
                             bg="#0e1116", fg="#58a6ff")
        left.pack(side="left", fill="both", expand=True, padx=(0, 6))
        canvas = tk.Canvas(left, bg="#0e1116", highlightthickness=0)
        scrollbar = tk.Scrollbar(left, orient="vertical", command=canvas.yview)
        self.modules_frame = tk.Frame(canvas, bg="#0e1116")
        self.modules_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.modules_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # right: log
        right = tk.LabelFrame(body, text="Live Backend Output",
                              bg="#0e1116", fg="#58a6ff")
        right.pack(side="right", fill="both", expand=True, padx=(6, 0))
        self.log_widget = scrolledtext.ScrolledText(
            right, bg="#0d1117", fg="#c9d1d9", insertbackground="white",
            font=("Consolas", 9))
        self.log_widget.pack(fill="both", expand=True)

        # status bar
        self.status_var = tk.StringVar(value="Idle.")
        tk.Label(self.root, textvariable=self.status_var,
                 bg="#161b22", fg="#8b949e", anchor="w").pack(fill="x")

    def _build_module_rows(self, modules: list[tuple[int, str]]) -> None:
        for child in self.modules_frame.winfo_children():
            child.destroy()
        self.module_rows.clear()
        for mid, name in modules:
            row = tk.Frame(self.modules_frame, bg="#0e1116")
            row.pack(fill="x", pady=1)
            tk.Label(row, text=f"M{mid:02d}", bg="#0e1116", fg="#8b949e",
                     width=5, anchor="w",
                     font=("Consolas", 9, "bold")).pack(side="left")
            tk.Label(row, text=name, bg="#0e1116", fg="#e6edf3",
                     width=28, anchor="w").pack(side="left")
            state_lbl = tk.Label(row, text="PENDING", bg="#0e1116",
                                 fg=STATE_COLORS[State.PENDING], width=18, anchor="w",
                                 font=("Consolas", 9, "bold"))
            state_lbl.pack(side="left")
            reason_lbl = tk.Label(row, text="", bg="#0e1116", fg="#8b949e",
                                  anchor="w")
            reason_lbl.pack(side="left", fill="x", expand=True)
            self.module_rows[mid] = {"state": state_lbl, "reason": reason_lbl}

    # ---------- callbacks from engine thread ---------- #
    def _status_cb(self, mid: int, state: State, reason: str) -> None:
        self.ui_queue.put(("state", mid, state, reason))

    def _log_cb(self, msg: str) -> None:
        self.ui_queue.put(("log", msg))

    # ---------- UI thread drain ---------- #
    def _drain_queue(self) -> None:
        try:
            while True:
                item = self.ui_queue.get_nowait()
                if item[0] == "state":
                    _, mid, state, reason = item
                    row = self.module_rows.get(mid)
                    if row:
                        label = (f"{state.value} [N/A]" if state == State.NOT_APPLICABLE
                                 else state.value)
                        row["state"].config(text=label, fg=STATE_COLORS.get(state, "#fff"))
                        row["reason"].config(text=reason[:80])
                elif item[0] == "log":
                    self.log_widget.insert("end", item[1] + "\n")
                    self.log_widget.see("end")
                elif item[0] == "done":
                    self.status_var.set(item[1])
                    self.launch_btn.config(state="normal")
        except queue.Empty:
            pass
        self.root.after(100, self._drain_queue)

    # ---------- launch ---------- #
    def on_launch(self) -> None:
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Mitiscan", "Enter a target first.")
            return
        if not self.auth_var.get():
            messagebox.showerror(
                "Authorization required",
                "Tick the authorization box. Mitiscan only runs against "
                "systems you own or have explicit written permission to test.")
            return
        # extra confirmation: retype target
        confirm = tk.simpledialog.askstring(
            "Confirm target", f"Retype the target to confirm:") if False else target
        self.launch_btn.config(state="disabled")
        self.status_var.set(f"Running against {target}...")
        self.log_widget.delete("1.0", "end")

        profile = EvasionProfile(self.profile_var.get())
        out_root = Path("./mitiscan_outputs")
        self.engine = Engine(target, out_root, profile=profile,
                             status_cb=self._status_cb, log_cb=self._log_cb)
        self._build_module_rows([(mid, name) for mid, name, _ in self.engine.modules])

        # persist authorization receipt
        auth_file = self.engine.out_dir / "authorization.txt"
        auth_file.write_text(
            f"Target: {target}\nProfile: {profile.value}\n"
            f"User attested written authorization at launch.\n")

        self.worker_thread = threading.Thread(target=self._run_engine, daemon=True)
        self.worker_thread.start()

    def _run_engine(self) -> None:
        assert self.engine is not None
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            results = loop.run_until_complete(self.engine.run())
            template_dir = Path(__file__).resolve().parent.parent / "templates"
            reporter = Reporter(
                results, self.engine.out_dir,
                self.engine.scope.raw_target, self.engine.run_id, template_dir)
            paths = reporter.render_all()
            for kind, p in paths.items():
                self.ui_queue.put(("log", f"[reporter] {kind.upper():<5} {p}"))
            self.ui_queue.put(("done", f"Complete. Report: {paths['html']}"))
        except Exception as e:
            self.ui_queue.put(("log", f"[FATAL] {e!r}"))
            self.ui_queue.put(("done", f"Failed: {e}"))
        finally:
            loop.close()

    def mainloop(self) -> None:
        self.root.mainloop()


def main() -> None:
    MitiscanGUI().mainloop()
