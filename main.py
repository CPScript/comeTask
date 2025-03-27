#!/usr/bin/env python3

import os
import sys
import time
import threading
import psutil
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import numpy as np
import socket
import struct
import ctypes
import platform

try:
    import GPUtil
    GPU_AVAILABLE = True
except ImportError:
    GPU_AVAILABLE = False

try:
    import py_cpuinfo
    CPUINFO_AVAILABLE = True
except ImportError:
    CPUINFO_AVAILABLE = False

try:
    import pynvml
    NVML_AVAILABLE = True
    pynvml.nvmlInit()
except ImportError:
    NVML_AVAILABLE = False

HISTORY_LENGTH = 60
REFRESH_INTERVAL = 1000

DARK_BG = "#1e1e1e"
DARKER_BG = "#141414"
DARK_TEXT = "#e0e0e0"
ACCENT_COLOR = "#007acc"
GRAPH_BG = "#252525"
HIGHLIGHT_BG = "#2d2d2d"
BORDER_COLOR = "#3d3d3d"
ERROR_COLOR = "#ff5252"
SUCCESS_COLOR = "#6cc64b"
WARNING_COLOR = "#ffcc00"

COLORS = {
    "cpu": "#f44336",
    "memory": "#2196f3",
    "disk": "#ff9800",
    "network": "#4caf50",
    "other": "#9c27b0",
    "accent": ACCENT_COLOR
}

class MemoryBlock:
    def __init__(self, start_addr, size, type_str, permissions, details=""):
        self.start_addr = start_addr
        self.size = size
        self.type = type_str
        self.permissions = permissions
        self.details = details
        
    def __str__(self):
        return f"0x{self.start_addr:016x} - 0x{self.start_addr + self.size:016x} {self.permissions} {self.type} {self.details}"

class TabManager:
    def __init__(self, parent):
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        self.tabs = {}
        
    def add_tab(self, name):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=name)
        self.tabs[name] = frame
        return frame
        
    def get_tab(self, name):
        return self.tabs.get(name)
        
class RealTimeGraph:
    def __init__(self, parent, title, y_label, max_y=100, num_plots=1, labels=None):
        self.data = [[] for _ in range(num_plots)]
        self.max_points = HISTORY_LENGTH
        self.max_y = max_y
        
        self.fig = Figure(figsize=(3, 1.3), dpi=100)
        self.fig.patch.set_facecolor(GRAPH_BG)
        
        self.ax = self.fig.add_subplot(111)
        self.ax.set_title(title, color=DARK_TEXT, fontsize=9)
        self.ax.set_ylabel(y_label, color=DARK_TEXT, fontsize=8)
        self.ax.set_ylim(0, max_y)
        self.ax.set_xlim(0, self.max_points)
        self.ax.grid(True, color=BORDER_COLOR, linestyle='-', linewidth=0.5, alpha=0.5)
        self.ax.set_facecolor(GRAPH_BG)
        
        self.ax.tick_params(axis='both', colors=DARK_TEXT, labelsize=7)
        self.ax.spines['bottom'].set_color(BORDER_COLOR)
        self.ax.spines['left'].set_color(BORDER_COLOR)
        self.ax.spines['top'].set_color(BORDER_COLOR)
        self.ax.spines['right'].set_color(BORDER_COLOR)
        
        self.ax.set_xticklabels([])
        
        self.lines = []
        for i in range(num_plots):
            line, = self.ax.plot([], [], '-', linewidth=1.3)
            self.lines.append(line)
            
        if labels:
            self.ax.legend(self.lines, labels, loc='upper right', fontsize=7, 
                          framealpha=0.7, facecolor=GRAPH_BG, edgecolor=BORDER_COLOR,
                          labelcolor=DARK_TEXT)
            
        self.canvas = FigureCanvasTkAgg(self.fig, master=parent)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        self.fig.tight_layout(pad=0.5)
        
    def update(self, values):
        for i, value in enumerate(values):
            if i >= len(self.data):
                continue
                
            data_list = self.data[i]
            data_list.append(value)
            if len(data_list) > self.max_points:
                data_list.pop(0)
                
            self.lines[i].set_data(range(len(data_list)), data_list)
            
        self.fig.canvas.draw_idle()
        self.fig.canvas.flush_events()
        
class MemoryMapVisualizer:
    def __init__(self, parent, system_monitor):
        self.parent = parent
        self.system_monitor = system_monitor
        self.memory_blocks = []
        self.selected_pid = None
        
        ctrl_frame = ttk.Frame(parent)
        ctrl_frame.pack(fill=tk.X, padx=2, pady=2)
        
        ttk.Label(ctrl_frame, text="Process:").pack(side=tk.LEFT, padx=2)
        self.process_combo = ttk.Combobox(ctrl_frame, width=35)
        self.process_combo.pack(side=tk.LEFT, padx=2)
        self.process_combo.bind("<<ComboboxSelected>>", self.on_process_selected)
        
        ttk.Button(ctrl_frame, text="Refresh", command=self.refresh_process_list).pack(side=tk.LEFT, padx=2)
        
        map_frame = ttk.Frame(parent)
        map_frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        self.canvas = tk.Canvas(map_frame, bg=DARK_BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(map_frame, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=scrollbar.set)
        
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.canvas.bind("<Configure>", self.on_canvas_configure)
        self.canvas.bind("<Button-1>", self.on_canvas_click)
        
        self.tooltip = tk.Label(self.canvas, bg=DARKER_BG, fg=DARK_TEXT, 
                            relief="solid", borderwidth=1)
        self.tooltip.place_forget()
        
        self.refresh_process_list()
        
    def refresh_process_list(self):
        processes = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                processes.append(f"{proc.info['pid']}: {proc.info['name']}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
                
        self.process_combo['values'] = processes
        
    def on_process_selected(self, event):
        selection = self.process_combo.get()
        if selection:
            try:
                self.selected_pid = int(selection.split(':')[0])
                self.update_memory_map()
            except (ValueError, IndexError):
                pass
                
    def update_memory_map(self):
        if not self.selected_pid:
            return
            
        try:
            self.memory_blocks = self.get_process_memory_map(self.selected_pid)
            self.draw_memory_map()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            messagebox.showerror("Error", f"Cannot access process memory: {e}")
            
    def get_process_memory_map(self, pid):
        memory_blocks = []

        try:
            process = psutil.Process(pid)

            if hasattr(process, "memory_maps") and callable(process.memory_maps):
                for mmap in process.memory_maps(grouped=False):
                    block = MemoryBlock(
                        int(mmap.addr.split('-')[0], 16),
                        int(mmap.addr.split('-')[1], 16) - int(mmap.addr.split('-')[0], 16),
                        mmap.path if mmap.path else "[anonymous]",
                        mmap.perms,
                        f"RSS: {mmap.rss:,} bytes"
                    )
                    memory_blocks.append(block)
            else:
                if platform.system() == "Linux":
                    memory_blocks = self._get_linux_memory_map(pid)
                elif platform.system() == "Windows":
                    memory_blocks = self._get_windows_memory_map(pid)
                elif platform.system() == "Darwin":
                    memory_blocks = self._get_macos_memory_map(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError) as e:
            messagebox.showerror("Error", f"Cannot access process memory: {e}")

        return memory_blocks

    def _get_linux_memory_map(self, pid):
        memory_blocks = []

        try:
            with open(f"/proc/{pid}/maps", "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 5:
                        addr_range, perms, offset, dev, inode = parts[:5]
                        path = " ".join(parts[5:]) if len(parts) > 5 else "[anonymous]"

                        addr_start, addr_end = addr_range.split("-")
                        start_addr = int(addr_start, 16)
                        end_addr = int(addr_end, 16)
                        size = end_addr - start_addr

                        block = MemoryBlock(
                            start_addr,
                            size,
                            path,
                            perms,
                            f"Offset: 0x{offset}, Dev: {dev}, Inode: {inode}"
                        )
                        memory_blocks.append(block)
        except Exception as e:
            print(f"Error reading Linux memory map: {e}")

        return memory_blocks

    def _get_windows_memory_map(self, pid):
        memory_blocks = []

        try:
            if platform.architecture()[0] == "64bit":
                class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                    _fields_ = [
                        ("BaseAddress", ctypes.c_ulonglong),
                        ("AllocationBase", ctypes.c_ulonglong),
                        ("AllocationProtect", ctypes.c_ulong),
                        ("__alignment1", ctypes.c_ulong),
                        ("RegionSize", ctypes.c_ulonglong),
                        ("State", ctypes.c_ulong),
                        ("Protect", ctypes.c_ulong),
                        ("Type", ctypes.c_ulong),
                        ("__alignment2", ctypes.c_ulong)
                    ]
            else:
                class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                    _fields_ = [
                        ("BaseAddress", ctypes.c_ulong),
                        ("AllocationBase", ctypes.c_ulong),
                        ("AllocationProtect", ctypes.c_ulong),
                        ("RegionSize", ctypes.c_ulong),
                        ("State", ctypes.c_ulong),
                        ("Protect", ctypes.c_ulong),
                        ("Type", ctypes.c_ulong)
                    ]

            PAGE_NOACCESS = 0x01
            PAGE_READONLY = 0x02
            PAGE_READWRITE = 0x04
            PAGE_WRITECOPY = 0x08
            PAGE_EXECUTE = 0x10
            PAGE_EXECUTE_READ = 0x20
            PAGE_EXECUTE_READWRITE = 0x40
            PAGE_EXECUTE_WRITECOPY = 0x80

            MEM_COMMIT = 0x1000
            MEM_FREE = 0x10000
            MEM_RESERVE = 0x2000

            MEM_IMAGE = 0x1000000
            MEM_MAPPED = 0x40000
            MEM_PRIVATE = 0x20000

            PROCESS_QUERY_INFORMATION = 0x0400
            PROCESS_VM_READ = 0x0010

            kernel32 = ctypes.windll.kernel32
            h_process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)

            if h_process:
                try:
                    mbi = MEMORY_BASIC_INFORMATION()
                    size = ctypes.sizeof(mbi)
                    address = 0

                    while kernel32.VirtualQueryEx(h_process, address, ctypes.byref(mbi), size):
                        if mbi.State == MEM_COMMIT:
                            perm_str = ""
                            if mbi.Protect & PAGE_READONLY or mbi.Protect & PAGE_READWRITE or mbi.Protect & PAGE_EXECUTE_READ or mbi.Protect & PAGE_EXECUTE_READWRITE:
                                perm_str += "r"
                            else:
                                perm_str += "-"

                            if mbi.Protect & PAGE_READWRITE or mbi.Protect & PAGE_EXECUTE_READWRITE:
                                perm_str += "w"
                            else:
                                perm_str += "-"

                            if mbi.Protect & PAGE_EXECUTE or mbi.Protect & PAGE_EXECUTE_READ or mbi.Protect & PAGE_EXECUTE_READWRITE:
                                perm_str += "x"
                            else:
                                perm_str += "-"

                            if mbi.Type == MEM_IMAGE:
                                type_str = "Image"
                            elif mbi.Type == MEM_MAPPED:
                                type_str = "Mapped"
                            elif mbi.Type == MEM_PRIVATE:
                                type_str = "Private"
                            else:
                                type_str = "Unknown"

                            block = MemoryBlock(
                                mbi.BaseAddress,
                                mbi.RegionSize,
                                type_str,
                                perm_str,
                                f"Protection: 0x{mbi.Protect:X}"
                            )
                            memory_blocks.append(block)

                        address += mbi.RegionSize
                finally:
                    kernel32.CloseHandle(h_process)
        except Exception as e:
            print(f"Error reading Windows memory map: {e}")

        return memory_blocks

    def _get_macos_memory_map(self, pid):
        memory_blocks = []

        try:
            import subprocess

            output = subprocess.check_output(['vmmap', str(pid)], universal_newlines=True)

            in_regions = False
            for line in output.splitlines():
                if "==== Writable regions for process" in line:
                    in_regions = True
                    continue
                    
                if in_regions and line.strip() and not line.startswith("=="):
                    parts = line.split()
                    if len(parts) >= 7:
                        try:
                            start_addr = int(parts[0].split('-')[0], 16)
                            end_addr = int(parts[0].split('-')[1], 16)
                            size = end_addr - start_addr

                            perms = ""
                            if "r" in parts[2]:
                                perms += "r"
                            else:
                                perms += "-"
                            if "w" in parts[2]:
                                perms += "w"
                            else:
                                perms += "-"
                            if "x" in parts[2]:
                                perms += "x"
                            else:
                                perms += "-"

                            description = " ".join(parts[6:])

                            block = MemoryBlock(
                                start_addr,
                                size,
                                description,
                                perms,
                                f"Mode: {parts[1]}, {parts[3]} {parts[4]} {parts[5]}"
                            )
                            memory_blocks.append(block)
                        except (ValueError, IndexError):
                            continue
        except Exception as e:
            print(f"Error reading macOS memory map: {e}")

        return memory_blocks
            
    def draw_memory_map(self):
        self.canvas.delete("all")
        
        if not self.memory_blocks:
            self.canvas.create_text(
                self.canvas.winfo_width() // 2,
                20,
                text="No memory mapping data available",
                fill=ERROR_COLOR,
                font=("Arial", 9)
            )
            return
            
        canvas_width = self.canvas.winfo_width()
        y_pos = 5
        block_height = 18
        
        self.memory_blocks.sort(key=lambda x: x.start_addr)
        
        min_addr = min(block.start_addr for block in self.memory_blocks)
        max_addr = max(block.start_addr + block.size for block in self.memory_blocks)
        addr_range = max_addr - min_addr
        
        for block in self.memory_blocks:
            rel_pos = (block.start_addr - min_addr) / addr_range
            rel_size = block.size / addr_range
            
            x1 = int(rel_pos * (canvas_width - 60)) + 30
            x2 = int((rel_pos + rel_size) * (canvas_width - 60)) + 30
            width = max(x2 - x1, 2)
            
            color = "#555555"
            if "rwx" in block.permissions:
                color = "#a83232"
            elif "r-x" in block.permissions or "--x" in block.permissions:
                color = "#a85c32"
            elif "rw-" in block.permissions:
                color = "#3259a8"
            elif "r--" in block.permissions:
                color = "#32a85a"
                
            block_id = self.canvas.create_rectangle(x1, y_pos, x1 + width, y_pos + block_height, 
                                                fill=color, outline=BORDER_COLOR)
            self.canvas.tag_bind(block_id, "<Enter>", lambda e, b=block: self.show_tooltip(e, b))
            self.canvas.tag_bind(block_id, "<Leave>", lambda e: self.hide_tooltip())
            
            if width > 40:
                addr_text = f"0x{block.start_addr:x}"
                self.canvas.create_text(x1 + 5, y_pos + block_height // 2, 
                                    text=addr_text, anchor=tk.W, 
                                    font=("Consolas", 7), fill=DARK_TEXT)
                
            y_pos += block_height + 2
            
        self.canvas.configure(scrollregion=(0, 0, canvas_width, y_pos + 5))
        
    def on_canvas_configure(self, event):
        if self.memory_blocks:
            self.draw_memory_map()
            
    def on_canvas_click(self, event):
        pass
        
    def show_tooltip(self, event, block):
        tooltip_text = f"Address: 0x{block.start_addr:x} - 0x{block.start_addr + block.size:x}\n"
        tooltip_text += f"Size: {block.size:,} bytes\n"
        tooltip_text += f"Permissions: {block.permissions}\n"
        tooltip_text += f"Type: {block.type}\n"
        if block.details:
            tooltip_text += f"Details: {block.details}"
            
        self.tooltip.configure(text=tooltip_text)
        self.tooltip.place(x=event.x + 10, y=event.y + 10)
        
    def hide_tooltip(self):
        self.tooltip.place_forget()

class ProcessMonitor:
    def __init__(self, parent):
        self.parent = parent
        
        ctrl_frame = ttk.Frame(parent)
        ctrl_frame.pack(fill=tk.X, padx=2, pady=2)
        
        ttk.Label(ctrl_frame, text="Filter:").pack(side=tk.LEFT, padx=2)
        self.filter_entry = ttk.Entry(ctrl_frame, width=15)
        self.filter_entry.pack(side=tk.LEFT, padx=2)
        self.filter_entry.bind("<Return>", lambda e: self.refresh_process_list())
        
        ttk.Button(ctrl_frame, text="Refresh", command=self.refresh_process_list, 
                 width=6).pack(side=tk.LEFT, padx=2)
        
        ttk.Label(ctrl_frame, text="Sort:").pack(side=tk.LEFT, padx=2)
        self.sort_var = tk.StringVar()
        sort_options = ["CPU %", "Memory %", "Name", "PID"]
        self.sort_combo = ttk.Combobox(ctrl_frame, textvariable=self.sort_var, values=sort_options, 
                                     width=8)
        self.sort_combo.current(0)
        self.sort_combo.pack(side=tk.LEFT, padx=2)
        self.sort_combo.bind("<<ComboboxSelected>>", lambda e: self.refresh_process_list())
        
        self.tree = ttk.Treeview(parent, columns=("pid", "name", "cpu", "memory", "threads", "status"), 
                               height=12)
        
        self.tree.heading("#0", text="")
        self.tree.heading("pid", text="PID")
        self.tree.heading("name", text="Name")
        self.tree.heading("cpu", text="CPU %")
        self.tree.heading("memory", text="Mem %")
        self.tree.heading("threads", text="Thds")
        self.tree.heading("status", text="Status")
        
        self.tree.column("#0", width=0, stretch=tk.NO)
        self.tree.column("pid", width=60, anchor=tk.CENTER)
        self.tree.column("name", width=160)
        self.tree.column("cpu", width=60, anchor=tk.CENTER)
        self.tree.column("memory", width=60, anchor=tk.CENTER)
        self.tree.column("threads", width=40, anchor=tk.CENTER)
        self.tree.column("status", width=70, anchor=tk.CENTER)
        
        vsb = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(parent, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.context_menu = tk.Menu(self.tree, tearoff=0, bg=DARKER_BG, fg=DARK_TEXT, 
                                 activebackground=HIGHLIGHT_BG, activeforeground=DARK_TEXT)
        self.context_menu.add_command(label="Kill Process", command=self.kill_selected_process)
        self.context_menu.add_command(label="View Memory Map", command=self.view_memory_map)
        self.tree.bind("<Button-3>", self.show_context_menu)
        
        self.process_data = {}
        self.refresh_process_list()
        
    def refresh_process_list(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        filter_text = self.filter_entry.get().lower()
        
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'num_threads', 'status']):
            try:
                proc_info = proc.info
                
                if filter_text and filter_text not in proc_info['name'].lower():
                    continue
                    
                pid = proc_info['pid']
                name = proc_info['name']
                
                if pid in self.process_data:
                    cpu_percent = self.process_data[pid].get('cpu_percent', 0)
                else:
                    cpu_percent = proc_info['cpu_percent'] or 0
                    
                memory_percent = proc_info['memory_percent'] or 0
                threads = proc_info['num_threads']
                status = proc_info['status']
                
                self.process_data[pid] = {
                    'name': name,
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory_percent,
                    'threads': threads,
                    'status': status
                }
                
                processes.append((pid, name, cpu_percent, memory_percent, threads, status))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
                
        sort_by = self.sort_var.get()
        if sort_by == "CPU %":
            processes.sort(key=lambda x: x[2], reverse=True)
        elif sort_by == "Memory %":
            processes.sort(key=lambda x: x[3], reverse=True)
        elif sort_by == "Name":
            processes.sort(key=lambda x: x[1].lower())
        elif sort_by == "PID":
            processes.sort(key=lambda x: x[0])
            
        for proc in processes:
            pid, name, cpu_percent, memory_percent, threads, status = proc
            self.tree.insert("", tk.END, values=(pid, name, f"{cpu_percent:.1f}", f"{memory_percent:.1f}", threads, status))
            
    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
            
    def kill_selected_process(self):
        if not self.tree.selection():
            return
            
        item = self.tree.selection()[0]
        pid = int(self.tree.item(item, "values")[0])
        
        confirm = messagebox.askyesno("Confirm", f"Terminate process {pid}?")
        if confirm:
            try:
                process = psutil.Process(pid)
                process.terminate()
                messagebox.showinfo("Success", f"Process {pid} terminated")
                self.refresh_process_list()
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                messagebox.showerror("Error", f"Cannot terminate process: {e}")
                
    def view_memory_map(self):
        if not self.tree.selection():
            return
            
        item = self.tree.selection()[0]
        pid = int(self.tree.item(item, "values")[0])
        
        win = tk.Toplevel(self.parent)
        win.title(f"Memory Map - PID {pid}")
        win.geometry("700x400")
        win.configure(bg=DARK_BG)
        
        apply_dark_theme(win)
        
        MemoryMapVisualizer(win, None).process_combo.set(f"{pid}: {self.tree.item(item, 'values')[1]}")
        
class NetworkMonitor:
    def __init__(self, parent):
        self.parent = parent
        
        self.net_stats = psutil.net_io_counters(pernic=True)
        self.prev_stats = self.net_stats
        
        graph_frame = ttk.Frame(parent)
        graph_frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        ctrl_frame = ttk.Frame(graph_frame)
        ctrl_frame.pack(fill=tk.X)
        
        ttk.Label(ctrl_frame, text="Interface:").pack(side=tk.LEFT, padx=2)
        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(ctrl_frame, textvariable=self.iface_var, width=18)
        self.iface_combo.pack(side=tk.LEFT, padx=2)
        self.iface_combo.bind("<<ComboboxSelected>>", self.on_interface_selected)
        
        self.update_interfaces()
        
        self.graph = RealTimeGraph(
            graph_frame,
            "Network Activity",
            "KB/s",
            max_y=100,
            num_plots=2,
            labels=["Download", "Upload"]
        )
        
        self.graph.lines[0].set_color(COLORS["network"])
        self.graph.lines[1].set_color(COLORS["cpu"])
        
        conn_frame = ttk.Frame(parent)
        conn_frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        self.tree = ttk.Treeview(conn_frame, columns=("proto", "local", "remote", "status", "pid", "process"), 
                               height=8)
        
        self.tree.heading("#0", text="")
        self.tree.heading("proto", text="Proto")
        self.tree.heading("local", text="Local Address")
        self.tree.heading("remote", text="Remote Address")
        self.tree.heading("status", text="Status")
        self.tree.heading("pid", text="PID")
        self.tree.heading("process", text="Process")
        
        self.tree.column("#0", width=0, stretch=tk.NO)
        self.tree.column("proto", width=50, anchor=tk.CENTER)
        self.tree.column("local", width=130)
        self.tree.column("remote", width=130)
        self.tree.column("status", width=70, anchor=tk.CENTER)
        self.tree.column("pid", width=50, anchor=tk.CENTER)
        self.tree.column("process", width=120)
        
        vsb = ttk.Scrollbar(conn_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, expand=True)
        
    def update_interfaces(self):
        interfaces = list(psutil.net_if_stats().keys())
        self.iface_combo['values'] = interfaces
        
        if interfaces and not self.iface_var.get():
            self.iface_combo.current(0)
            
    def on_interface_selected(self, event):
        for data_list in self.graph.data:
            data_list.clear()
            
    def update(self):
        self.prev_stats = self.net_stats
        self.net_stats = psutil.net_io_counters(pernic=True)
        
        iface = self.iface_var.get()
        if iface and iface in self.net_stats and iface in self.prev_stats:
            current = self.net_stats[iface]
            prev = self.prev_stats[iface]
            
            bytes_recv = (current.bytes_recv - prev.bytes_recv) / 1024
            bytes_sent = (current.bytes_sent - prev.bytes_sent) / 1024
            
            self.graph.update([bytes_recv, bytes_sent])
            
            max_value = max(bytes_recv, bytes_sent, 1)
            if max_value > self.graph.max_y:
                self.graph.max_y = max_value * 1.5
                self.graph.ax.set_ylim(0, self.graph.max_y)
                
        self.update_connections()
        
    def update_connections(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        connections = psutil.net_connections(kind='inet')
        
        process_info = {}
        
        for conn in connections[:50]:
            proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            
            if conn.laddr:
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
            else:
                laddr = "N/A"
                
            if conn.raddr:
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}"
            else:
                raddr = "N/A"
                
            status = conn.status if conn.status else "NONE"
            pid = conn.pid if conn.pid else "N/A"
            
            process = "N/A"
            if pid != "N/A":
                if pid not in process_info:
                    try:
                        process_info[pid] = psutil.Process(pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        process_info[pid] = "Unknown"
                process = process_info[pid]
                
            self.tree.insert("", tk.END, values=(proto, laddr, raddr, status, pid, process))

class DiskMonitor:
    def __init__(self, parent):
        self.parent = parent
        
        self.disk_io_stats = psutil.disk_io_counters(perdisk=True)
        self.prev_stats = self.disk_io_stats
        
        part_frame = ttk.LabelFrame(parent, text="Disk Partitions")
        part_frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        self.part_tree = ttk.Treeview(part_frame, columns=("device", "mountpoint", "fstype", "total", "used", "free", "percent"),
                                    height=4)
                                    
        self.part_tree.heading("#0", text="")
        self.part_tree.heading("device", text="Device")
        self.part_tree.heading("mountpoint", text="Mount")
        self.part_tree.heading("fstype", text="Type")
        self.part_tree.heading("total", text="Total")
        self.part_tree.heading("used", text="Used")
        self.part_tree.heading("free", text="Free")
        self.part_tree.heading("percent", text="Usage")
        
        self.part_tree.column("#0", width=0, stretch=tk.NO)
        self.part_tree.column("device", width=80)
        self.part_tree.column("mountpoint", width=80)
        self.part_tree.column("fstype", width=50, anchor=tk.CENTER)
        self.part_tree.column("total", width=70, anchor=tk.CENTER)
        self.part_tree.column("used", width=70, anchor=tk.CENTER)
        self.part_tree.column("free", width=70, anchor=tk.CENTER)
        self.part_tree.column("percent", width=60, anchor=tk.CENTER)
        
        part_vsb = ttk.Scrollbar(part_frame, orient="vertical", command=self.part_tree.yview)
        self.part_tree.configure(yscrollcommand=part_vsb.set)
        
        part_vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.part_tree.pack(fill=tk.BOTH, expand=True)
        
        io_frame = ttk.LabelFrame(parent, text="Disk I/O Activity")
        io_frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        self.graph = RealTimeGraph(
            io_frame,
            "Disk I/O",
            "MB/s",
            max_y=10,
            num_plots=2,
            labels=["Read", "Write"]
        )
        
        self.graph.lines[0].set_color(COLORS["memory"])
        self.graph.lines[1].set_color(COLORS["disk"])
        
        self.update_partitions()
        
    def update_partitions(self):
        for item in self.part_tree.get_children():
            self.part_tree.delete(item)
            
        partitions = psutil.disk_partitions(all=True)
        
        for part in partitions:
            try:
                usage = psutil.disk_usage(part.mountpoint)
                
                total = self.format_size(usage.total)
                used = self.format_size(usage.used)
                free = self.format_size(usage.free)
                percent = f"{usage.percent}%"
                
                self.part_tree.insert("", tk.END, values=(
                    part.device,
                    part.mountpoint,
                    part.fstype,
                    total,
                    used,
                    free,
                    percent
                ))
            except (PermissionError, OSError):
                self.part_tree.insert("", tk.END, values=(
                    part.device,
                    part.mountpoint,
                    part.fstype,
                    "N/A",
                    "N/A",
                    "N/A",
                    "N/A"
                ))
                
    def update(self):
        self.prev_stats = self.disk_io_stats
        self.disk_io_stats = psutil.disk_io_counters(perdisk=True)
        
        total_read = 0
        total_write = 0
        
        for disk, stats in self.disk_io_stats.items():
            if disk in self.prev_stats:
                prev = self.prev_stats[disk]
                
                read_bytes = stats.read_bytes - prev.read_bytes
                write_bytes = stats.write_bytes - prev.write_bytes
                
                total_read += read_bytes
                total_write += write_bytes
                
        total_read_mb = total_read / (1024 * 1024)
        total_write_mb = total_write / (1024 * 1024)
        
        self.graph.update([total_read_mb, total_write_mb])
        
        max_value = max(total_read_mb, total_write_mb, 0.1)
        if max_value > self.graph.max_y:
            self.graph.max_y = max_value * 1.5
            self.graph.ax.set_ylim(0, self.graph.max_y)
            
    def format_size(self, size_bytes):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} PB"

class CPUMonitor:
    def __init__(self, parent):
        self.parent = parent
        
        self.cpu_count = psutil.cpu_count(logical=True)
        self.physical_cores = psutil.cpu_count(logical=False)
        
        info_frame = ttk.Frame(parent)
        info_frame.pack(fill=tk.X, padx=2, pady=2)
        
        cpu_model = "Unknown"
        if CPUINFO_AVAILABLE:
            try:
                cpu_info = py_cpuinfo.get_cpu_info()
                cpu_model = cpu_info.get('brand_raw', "Unknown")
            except:
                pass
                
        model_label = ttk.Label(info_frame, text=f"CPU: {cpu_model}", font=("Arial", 8))
        model_label.pack(anchor=tk.W)
        
        ttk.Label(info_frame, text=f"Cores: {self.physical_cores} physical, {self.cpu_count} logical", 
               font=("Arial", 8)).pack(anchor=tk.W)
        
        overall_frame = ttk.Frame(parent)
        overall_frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        self.overall_graph = RealTimeGraph(
            overall_frame,
            "Total CPU Usage",
            "Usage %",
            max_y=100,
            num_plots=1
        )
        
        self.overall_graph.lines[0].set_color(COLORS["cpu"])
        
        cores_frame = ttk.Frame(parent)
        cores_frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        self.cores_graph = RealTimeGraph(
            cores_frame,
            "Per-Core Usage",
            "Usage %",
            max_y=100,
            num_plots=min(self.cpu_count, 16),
            labels=[f"#{i}" for i in range(min(self.cpu_count, 16))]
        )
        
        for i, line in enumerate(self.cores_graph.lines):
            line.set_color(self.get_color(i, min(self.cpu_count, 16)))
            
    def get_color(self, i, total):
        hue = i / total
        r, g, b = self.hsv_to_rgb(hue, 0.7, 0.8)
        return f"#{int(r*255):02x}{int(g*255):02x}{int(b*255):02x}"
        
    def hsv_to_rgb(self, h, s, v):
        if s == 0:
            return v, v, v
            
        h *= 6
        i = int(h)
        f = h - i
        p = v * (1 - s)
        q = v * (1 - s * f)
        t = v * (1 - s * (1 - f))
        
        if i == 0:
            return v, t, p
        elif i == 1:
            return q, v, p
        elif i == 2:
            return p, v, t
        elif i == 3:
            return p, q, v
        elif i == 4:
            return t, p, v
        else:
            return v, p, q
            
    def update(self):
        overall_usage = psutil.cpu_percent()
        self.overall_graph.update([overall_usage])
        
        per_core_usage = psutil.cpu_percent(percpu=True)
        self.cores_graph.update(per_core_usage[:min(self.cpu_count, 16)])

class MemoryMonitor:
    def __init__(self, parent):
        self.parent = parent
        
        info_frame = ttk.Frame(parent)
        info_frame.pack(fill=tk.X, padx=2, pady=2)
        
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        total_ram = self.format_size(mem.total)
        total_swap = self.format_size(swap.total)
        
        self.ram_label = ttk.Label(info_frame, text=f"RAM: {total_ram}", font=("Arial", 8))
        self.ram_label.pack(side=tk.LEFT, padx=10)
        
        self.swap_label = ttk.Label(info_frame, text=f"Swap: {total_swap}", font=("Arial", 8))
        self.swap_label.pack(side=tk.LEFT, padx=10)
        
        ram_frame = ttk.Frame(parent)
        ram_frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        self.ram_graph = RealTimeGraph(
            ram_frame,
            "RAM Usage",
            "GB",
            max_y=mem.total / (1024**3) * 1.1,
            num_plots=3,
            labels=["Used", "Cached", "Free"]
        )
        
        self.ram_graph.lines[0].set_color(COLORS["cpu"])
        self.ram_graph.lines[1].set_color(COLORS["memory"])
        self.ram_graph.lines[2].set_color(COLORS["network"])
        
        swap_frame = ttk.Frame(parent)
        swap_frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        self.swap_graph = RealTimeGraph(
            swap_frame,
            "Swap Usage",
            "GB",
            max_y=max(swap.total / (1024**3) * 1.1, 0.1),
            num_plots=1
        )
        
        self.swap_graph.lines[0].set_color(COLORS["other"])
        
    def update(self):
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        used = (mem.used - mem.cached) / (1024**3)
        cached = mem.cached / (1024**3)
        free = mem.free / (1024**3)
        
        self.ram_graph.update([used, cached, free])
        
        swap_used = swap.used / (1024**3)
        self.swap_graph.update([swap_used])
        
        self.ram_label.configure(text=f"RAM: {self.format_size(mem.total)} - Used: {mem.percent}%")
        self.swap_label.configure(text=f"Swap: {self.format_size(swap.total)} - Used: {swap.percent}%")
        
    def format_size(self, size_bytes):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} PB"

class GPUMonitor:
    def __init__(self, parent):
        self.parent = parent
        
        if not GPU_AVAILABLE and not NVML_AVAILABLE:
            label = ttk.Label(parent, text="GPU monitoring not available\nInstall GPUtil or pynvml package", 
                           font=("Arial", 8))
            label.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)
            return
            
        self.gpus = []
        
        if NVML_AVAILABLE:
            try:
                device_count = pynvml.nvmlDeviceGetCount()
                for i in range(device_count):
                    handle = pynvml.nvmlDeviceGetHandleByIndex(i)
                    name = pynvml.nvmlDeviceGetName(handle)
                    self.gpus.append({
                        'id': i,
                        'name': name,
                        'handle': handle,
                        'type': 'NVIDIA'
                    })
            except:
                pass
                
        if not self.gpus and GPU_AVAILABLE:
            try:
                for gpu in GPUtil.getGPUs():
                    self.gpus.append({
                        'id': gpu.id,
                        'name': gpu.name,
                        'handle': gpu,
                        'type': 'GPUtil'
                    })
            except:
                pass
                
        if not self.gpus:
            label = ttk.Label(parent, text="No GPUs detected or access denied")
            label.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)
            return
            
        self.gpu_notebook = ttk.Notebook(parent)
        self.gpu_notebook.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        self.gpu_tabs = []
        for gpu in self.gpus:
            tab = ttk.Frame(self.gpu_notebook)
            self.gpu_notebook.add(tab, text=f"GPU {gpu['id']}")
            self.gpu_tabs.append(tab)
            
            info_frame = ttk.Frame(tab)
            info_frame.pack(fill=tk.X, padx=2, pady=2)
            
            gpu_name = gpu['name']
            if len(gpu_name) > 30:
                gpu_name = gpu_name[:27] + "..."
                
            ttk.Label(info_frame, text=f"Model: {gpu_name}", font=("Arial", 8)).pack(anchor=tk.W)
            
            self.create_gpu_labels(gpu, info_frame)
            
            graph_frame = ttk.Frame(tab)
            graph_frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
            
            if gpu['type'] == 'NVIDIA':
                gpu['graph'] = RealTimeGraph(
                    graph_frame,
                    "GPU Usage",
                    "Usage %",
                    max_y=100,
                    num_plots=3,
                    labels=["GPU", "Memory", "Temp"]
                )
                
                gpu['graph'].lines[0].set_color(COLORS["cpu"])
                gpu['graph'].lines[1].set_color(COLORS["memory"])
                gpu['graph'].lines[2].set_color(COLORS["disk"])
            else:
                gpu['graph'] = RealTimeGraph(
                    graph_frame,
                    "GPU Usage",
                    "Usage %",
                    max_y=100,
                    num_plots=2,
                    labels=["GPU", "Memory"]
                )
                
                gpu['graph'].lines[0].set_color(COLORS["cpu"])
                gpu['graph'].lines[1].set_color(COLORS["memory"])
                
    def create_gpu_labels(self, gpu, parent):
        left_frame = ttk.Frame(parent)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=2, pady=2)
        
        right_frame = ttk.Frame(parent)
        right_frame.pack(side=tk.LEFT, fill=tk.Y, padx=2, pady=2)
        
        font = ("Arial", 8)
        
        gpu['util_label'] = ttk.Label(left_frame, text="Util: N/A", font=font)
        gpu['util_label'].pack(anchor=tk.W)
        
        gpu['mem_label'] = ttk.Label(left_frame, text="Mem: N/A", font=font)
        gpu['mem_label'].pack(anchor=tk.W)
        
        gpu['temp_label'] = ttk.Label(right_frame, text="Temp: N/A", font=font)
        gpu['temp_label'].pack(anchor=tk.W)
        
        gpu['power_label'] = ttk.Label(right_frame, text="Power: N/A", font=font)
        gpu['power_label'].pack(anchor=tk.W)
        
    def update(self):
        for gpu in self.gpus:
            try:
                if gpu['type'] == 'NVIDIA':
                    handle = gpu['handle']
                    
                    util = pynvml.nvmlDeviceGetUtilizationRates(handle)
                    gpu_util = util.gpu
                    mem_util = util.memory
                    
                    mem_info = pynvml.nvmlDeviceGetMemoryInfo(handle)
                    mem_total = mem_info.total / (1024**2)
                    mem_used = mem_info.used / (1024**2)
                    mem_free = mem_info.free / (1024**2)
                    mem_percent = (mem_used / mem_total) * 100
                    
                    temp = pynvml.nvmlDeviceGetTemperature(handle, 0)
                    
                    try:
                        power = pynvml.nvmlDeviceGetPowerUsage(handle) / 1000.0
                    except:
                        power = 0
                        
                    gpu['util_label'].configure(text=f"Util: {gpu_util}%")
                    gpu['mem_label'].configure(text=f"Mem: {mem_used:.0f}/{mem_total:.0f} MB ({mem_percent:.1f}%)")
                    gpu['temp_label'].configure(text=f"Temp: {temp}°C")
                    gpu['power_label'].configure(text=f"Power: {power:.1f}W")
                    
                    gpu['graph'].update([gpu_util, mem_percent, temp])
                else:
                    handle = gpu['handle']
                    
                    handle.update()
                    
                    gpu_util = handle.load * 100
                    mem_total = handle.memoryTotal
                    mem_used = handle.memoryUsed
                    mem_percent = (mem_used / mem_total) * 100
                    temp = handle.temperature
                    
                    gpu['util_label'].configure(text=f"Util: {gpu_util:.1f}%")
                    gpu['mem_label'].configure(text=f"Mem: {mem_used:.0f}/{mem_total:.0f} MB ({mem_percent:.1f}%)")
                    gpu['temp_label'].configure(text=f"Temp: {temp}°C")
                    
                    gpu['graph'].update([gpu_util, mem_percent])
            except Exception as e:
                pass

def apply_dark_theme(root):
    style = ttk.Style()
    
    style.theme_create("DarkTheme", parent="alt", settings={
        "TNotebook": {"configure": {"tabmargins": [2, 5, 2, 0], "background": DARKER_BG}},
        "TNotebook.Tab": {
            "configure": {"padding": [5, 2], "background": DARK_BG, "foreground": DARK_TEXT},
            "map": {"background": [("selected", HIGHLIGHT_BG)], "foreground": [("selected", DARK_TEXT)]}
        },
        "TFrame": {"configure": {"background": DARK_BG}},
        "TLabelframe": {"configure": {"background": DARK_BG, "foreground": DARK_TEXT}},
        "TLabelframe.Label": {"configure": {"background": DARK_BG, "foreground": DARK_TEXT}},
        "TLabel": {"configure": {"background": DARK_BG, "foreground": DARK_TEXT}},
        "TButton": {
            "configure": {"background": HIGHLIGHT_BG, "foreground": DARK_TEXT, "padding": [4, 2]},
            "map": {"background": [("active", ACCENT_COLOR)], "foreground": [("active", "white")]}
        },
        "TEntry": {"configure": {"fieldbackground": DARKER_BG, "foreground": DARK_TEXT, "insertcolor": DARK_TEXT}},
        "TCombobox": {
            "configure": {"fieldbackground": DARKER_BG, "background": DARKER_BG, "foreground": DARK_TEXT},
            "map": {"fieldbackground": [("readonly", DARKER_BG)], "background": [("readonly", DARKER_BG)]}
        },
        "TScrollbar": {
            "configure": {"background": DARK_BG, "troughcolor": DARKER_BG, "borderwidth": 0},
            "map": {"background": [("active", HIGHLIGHT_BG)]}
        },
        "Treeview": {
            "configure": {"background": DARKER_BG, "foreground": DARK_TEXT, "fieldbackground": DARKER_BG},
            "map": {"background": [("selected", ACCENT_COLOR)], "foreground": [("selected", "white")]}
        },
        "Treeview.Heading": {
            "configure": {"background": DARK_BG, "foreground": DARK_TEXT, "font": ("Arial", 8, "bold")},
            "map": {"background": [("active", HIGHLIGHT_BG)]}
        }
    })
    
    style.theme_use("DarkTheme")
    
    root.configure(bg=DARK_BG)
    for widget in root.winfo_children():
        if isinstance(widget, tk.Frame) or isinstance(widget, ttk.Frame):
            widget.configure(bg=DARK_BG)

class SystemMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("System Monitor")
        self.root.geometry("900x600")
        self.root.configure(bg=DARK_BG)
        
        apply_dark_theme(root)
        
        try:
            icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.ico")
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except:
            pass
            
        self.tab_manager = TabManager(root)
        
        cpu_tab = self.tab_manager.add_tab("CPU")
        self.cpu_monitor = CPUMonitor(cpu_tab)
        
        memory_tab = self.tab_manager.add_tab("Memory")
        self.memory_monitor = MemoryMonitor(memory_tab)
        
        disk_tab = self.tab_manager.add_tab("Disk")
        self.disk_monitor = DiskMonitor(disk_tab)
        
        network_tab = self.tab_manager.add_tab("Network")
        self.network_monitor = NetworkMonitor(network_tab)
        
        processes_tab = self.tab_manager.add_tab("Processes")
        self.process_monitor = ProcessMonitor(processes_tab)
        
        memmap_tab = self.tab_manager.add_tab("Memory Map")
        self.memmap_visualizer = MemoryMapVisualizer(memmap_tab, self)
        
        if GPU_AVAILABLE or NVML_AVAILABLE:
            gpu_tab = self.tab_manager.add_tab("GPU")
            self.gpu_monitor = GPUMonitor(gpu_tab)
        else:
            self.gpu_monitor = None
            
        self.create_menu()
        
        self.update_display()
        
    def create_menu(self):
        menubar = tk.Menu(self.root, bg=DARKER_BG, fg=DARK_TEXT, activebackground=HIGHLIGHT_BG, 
                       activeforeground="white", borderwidth=0)
        
        file_menu = tk.Menu(menubar, tearoff=0, bg=DARKER_BG, fg=DARK_TEXT, 
                         activebackground=HIGHLIGHT_BG, activeforeground="white")
        file_menu.add_command(label="Save Snapshot", command=self.save_snapshot)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        view_menu = tk.Menu(menubar, tearoff=0, bg=DARKER_BG, fg=DARK_TEXT, 
                         activebackground=HIGHLIGHT_BG, activeforeground="white")
        view_menu.add_command(label="Refresh", command=self.force_refresh)
        view_menu.add_separator()
        view_menu.add_command(label="CPU Details", command=lambda: self.tab_manager.notebook.select(0))
        view_menu.add_command(label="Memory Details", command=lambda: self.tab_manager.notebook.select(1))
        view_menu.add_command(label="Disk Details", command=lambda: self.tab_manager.notebook.select(2))
        view_menu.add_command(label="Network Details", command=lambda: self.tab_manager.notebook.select(3))
        view_menu.add_command(label="Process Details", command=lambda: self.tab_manager.notebook.select(4))
        menubar.add_cascade(label="View", menu=view_menu)
        
        tools_menu = tk.Menu(menubar, tearoff=0, bg=DARKER_BG, fg=DARK_TEXT, 
                         activebackground=HIGHLIGHT_BG, activeforeground="white")
        tools_menu.add_command(label="Process Explorer", command=self.show_process_explorer)
        tools_menu.add_command(label="Memory Dump", command=self.create_memory_dump)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        help_menu = tk.Menu(menubar, tearoff=0, bg=DARKER_BG, fg=DARK_TEXT, 
                         activebackground=HIGHLIGHT_BG, activeforeground="white")
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
        
    def update_display(self):
        self.cpu_monitor.update()
        self.memory_monitor.update()
        self.disk_monitor.update()
        self.network_monitor.update()
        
        if self.gpu_monitor:
            self.gpu_monitor.update()
            
        self.root.after(REFRESH_INTERVAL, self.update_display)
        
    def force_refresh(self):
        self.process_monitor.refresh_process_list()
        self.disk_monitor.update_partitions()
        self.network_monitor.update_interfaces()
        
    def save_snapshot(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
            
        try:
            with open(file_path, "w") as f:
                f.write("=== SYSTEM INFORMATION ===\n")
                f.write(f"Platform: {platform.platform()}\n")
                f.write(f"Python: {platform.python_version()}\n")
                f.write(f"Boot Time: {time.ctime(psutil.boot_time())}\n\n")
                
                f.write("=== CPU INFORMATION ===\n")
                f.write(f"Physical cores: {psutil.cpu_count(logical=False)}\n")
                f.write(f"Logical cores: {psutil.cpu_count(logical=True)}\n")
                f.write(f"Current frequency: {psutil.cpu_freq().current} MHz\n")
                f.write(f"Current usage: {psutil.cpu_percent()}%\n\n")
                
                f.write("=== MEMORY INFORMATION ===\n")
                mem = psutil.virtual_memory()
                swap = psutil.swap_memory()
                f.write(f"Total RAM: {mem.total / (1024**3):.2f} GB\n")
                f.write(f"Available RAM: {mem.available / (1024**3):.2f} GB\n")
                f.write(f"Used RAM: {mem.used / (1024**3):.2f} GB ({mem.percent}%)\n")
                f.write(f"Total Swap: {swap.total / (1024**3):.2f} GB\n")
                f.write(f"Used Swap: {swap.used / (1024**3):.2f} GB ({swap.percent}%)\n\n")
                
                f.write("=== DISK INFORMATION ===\n")
                for part in psutil.disk_partitions(all=True):
                    f.write(f"Device: {part.device}\n")
                    f.write(f"  Mountpoint: {part.mountpoint}\n")
                    f.write(f"  Type: {part.fstype}\n")
                    try:
                        usage = psutil.disk_usage(part.mountpoint)
                        f.write(f"  Total: {usage.total / (1024**3):.2f} GB\n")
                        f.write(f"  Used: {usage.used / (1024**3):.2f} GB ({usage.percent}%)\n")
                    except (PermissionError, OSError):
                        f.write("  Usage: N/A\n")
                    f.write("\n")
                    
                f.write("=== NETWORK INFORMATION ===\n")
                for nic, addrs in psutil.net_if_addrs().items():
                    f.write(f"Interface: {nic}\n")
                    for addr in addrs:
                        if addr.family == socket.AF_INET:
                            f.write(f"  IP: {addr.address}\n")
                        elif addr.family == socket.AF_INET6:
                            f.write(f"  IPv6: {addr.address}\n")
                        elif addr.family == psutil.AF_LINK:
                            f.write(f"  MAC: {addr.address}\n")
                    f.write("\n")
                    
                f.write("=== TOP PROCESSES ===\n")
                processes = []
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                    try:
                        processes.append((
                            proc.info['pid'],
                            proc.info['name'],
                            proc.info['cpu_percent'],
                            proc.info['memory_percent']
                        ))
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                        
                processes.sort(key=lambda x: x[2], reverse=True)
                
                for i, proc in enumerate(processes[:20]):
                    pid, name, cpu, mem = proc
                    f.write(f"{i+1}. {name} (PID: {pid})\n")
                    f.write(f"   CPU: {cpu:.1f}%, Memory: {mem:.1f}%\n")
                    
            messagebox.showinfo("Success", f"System snapshot saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Error saving snapshot: {e}")
            
    def show_process_explorer(self):
        window = tk.Toplevel(self.root)
        window.title("Process Explorer")
        window.geometry("750x500")
        window.configure(bg=DARK_BG)
        
        apply_dark_theme(window)
        
        ProcessMonitor(window)
        
    def create_memory_dump(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Create Memory Dump")
        dialog.geometry("350x160")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.configure(bg=DARK_BG)
        
        apply_dark_theme(dialog)
        
        ttk.Label(dialog, text="Select Process:").pack(pady=(10, 0))
        
        process_combo = ttk.Combobox(dialog, width=35)
        process_combo.pack(pady=(5, 10))
        
        processes = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                processes.append(f"{proc.info['pid']}: {proc.info['name']}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
                
        process_combo['values'] = processes
        
        button_frame = ttk.Frame(dialog)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Dump Memory", 
                command=lambda: self.do_memory_dump(dialog, process_combo.get())).pack(side=tk.RIGHT, padx=5)
        
    def do_memory_dump(self, dialog, process_str):
        if not process_str:
            messagebox.showerror("Error", "No process selected")
            return
            
        try:
            pid = int(process_str.split(':')[0])
            
            file_path = filedialog.asksaveasfilename(
                defaultextension=".dmp",
                filetypes=[("Memory Dump files", "*.dmp"), ("All files", "*.*")]
            )
            
            if not file_path:
                return
                
            try:
                if platform.system() == "Windows":
                    messagebox.showinfo("Information", "Full memory dumps require system tools like procdump or WinDbg.")
                else:
                    messagebox.showinfo("Information", 
                                        "Full memory dumps on Linux require tools like gcore.")
            except Exception as e:
                messagebox.showerror("Error", f"Error creating memory dump: {e}")
                
            messagebox.showinfo("Information", 
                               "For full memory dump functionality, use system-specific tools:\n"
                               "- Windows: procdump, WinDbg\n"
                               "- Linux: gcore, /proc/[pid]/mem")
        except Exception as e:
            messagebox.showerror("Error", f"Error: {e}")
            
        dialog.destroy()
        
    def show_about(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("About")
        dialog.geometry("300x120")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.configure(bg=DARK_BG)
        
        apply_dark_theme(dialog)
        
        about_text = """System Resource Monitor

Provides monitoring for system resources:
CPU, memory, disk, network, processes,
and memory mapping.
"""
        ttk.Label(dialog, text=about_text, justify=tk.CENTER).pack(padx=10, pady=10)
        ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=5)

if __name__ == "__main__":
    try:
        is_admin = False
        if platform.system() == "Windows":
            try:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                is_admin = False
        else:
            is_admin = os.geteuid() == 0
            
        if not is_admin:
            print("Warning: Some features may require administrator privileges.")
    except:
        pass
        
    root = tk.Tk()
    app = SystemMonitor(root)
    root.mainloop()
    
    if NVML_AVAILABLE:
        try:
            pynvml.nvmlShutdown()
        except:
            pass
