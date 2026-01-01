#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from PIL import Image, ImageTk
import threading
import time
import reputation
import main
import comparator
import json
import csv
import os
import pandas as pd
import ctypes
import dns_engine

class SeparatorGUI:
    def __init__(self, root):
        self.root = root
        
        # Windows Taskbar Icon Fix
        if os.name == 'nt':
            myappid = 'socti.toolkit.seprep.v2' # arbitrary string
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)

        self.root.title("SOCTI Toolkit")
        self.root.geometry("900x750")
        self.root.resizable(True, True)
        
        # Logo Setup
        self.logo_img = None
        try:
            logo_path = os.path.join(os.path.dirname(__file__), 'assets', 'logo.jpg')
            if os.path.exists(logo_path):
                img = Image.open(logo_path)
                # For Window Icon
                self.icon_photo = ImageTk.PhotoImage(img)
                self.root.iconphoto(True, self.icon_photo)
                
                # For Header Display (Resize for header)
                img_small = img.resize((40, 40), Image.Resampling.LANCZOS)
                self.logo_img = ImageTk.PhotoImage(img_small)
        except Exception as e:
            print(f"Warning: Failed to load logo: {e}")

        # Color Palettes
        self.colors = {
            'light': {
                'bg': '#f5f5f5',
                'fg': '#333333',
                'input_bg': '#ffffff',
                'input_fg': '#333333',
                'primary': '#e65100', # Burnt Orange
                'secondary_bg': '#e0e0e0',
                'header_fg': '#e65100'
            },
            'dark': {
                'bg': '#2b2b2b',
                'fg': '#e0e0e0',
                'input_bg': '#4a4a4a',
                'input_fg': '#ffffff',
                'primary': '#ff8c42',
                'secondary_bg': '#3a3a3a',
                'header_fg': '#ff8c42'
            }
        }
        
        self.current_theme = 'light'
        
        # Footer - Signature (Global)
        self.footer_label = tk.Label(root, text="made by DIO", font=('Arial', 8, 'italic'))
        self.footer_label.pack(side=tk.BOTTOM, anchor=tk.SE, padx=10, pady=2)
        
        # Global Header
        self.glo_header = ttk.Frame(root, padding=5)
        self.glo_header.pack(side=tk.TOP, fill='x') 
        
        # Logo in Header (Left)
        if self.logo_img:
            ttk.Label(self.glo_header, image=self.logo_img).pack(side='left', padx=(5, 10))
            
        ttk.Label(self.glo_header, text="SOCTI Toolkit", style='Title.TLabel', font=('Arial', 14, 'bold')).pack(side='left', anchor='center')
        
        self.btn_theme = ttk.Button(self.glo_header, text="Toggle Theme", command=self.toggle_theme, style='Secondary.TButton')
        self.btn_theme.pack(side='right', padx=10)

        # Notebook for Tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=True, fill='both', padx=5, pady=5)
        
        # Tab 1: SepRep (formerly Separator)
        self.sep_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.sep_frame, text='SepRep')
        self.create_separator_tab(self.sep_frame)
        
        # Tab 2: GT HostSplit (New)
        self.host_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.host_frame, text='HostSplit')
        self.create_hostsplit_tab(self.host_frame)
        
        # Tab 3: Asset Comparator
        self.comp_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.comp_frame, text='Asset Comparator')
        self.create_comparator_tab(self.comp_frame)
        
        # Initialize Logic Engines
        self.norm_engine = comparator.NormalizationEngine()
        self.comp_engine = comparator.ComparisonEngine()
        
        # Comparator Logic State
        self.comp_state = "raw"
        self.normalized_cache_a = []
        self.normalized_cache_b = []
        
        # Custom Config (Proxies & API Keys)
        self.config_file = 'settings.json'
        self.custom_config = self.load_settings()
        self.proxy_config = self.custom_config.get('proxy', {})

        # Apply initial theme
        self.apply_theme()

    def load_settings(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading settings: {e}")
        return {'proxy': {}, 'api_keys': {}}

    def save_settings(self):
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.custom_config, f, indent=4)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings: {e}")

    def toggle_theme(self):
        self.current_theme = 'dark' if self.current_theme == 'light' else 'light'
        self.apply_theme()

    def apply_theme(self):
        c = self.colors[self.current_theme]
        
        self.root.configure(bg=c['bg'])
        self.footer_label.configure(bg=c['bg'], fg=c['fg'])
        
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure(".", background=c['bg'], foreground=c['fg'])
        style.configure('Main.TFrame', background=c['bg'])
        style.configure('TLabel', background=c['bg'], foreground=c['fg'])
        style.configure('Title.TLabel', foreground=c['header_fg'], font=('Arial', 18, 'bold'))
        style.configure('Logo.TLabel', foreground=c['fg'], font=('Arial', 12, 'bold'))
        style.configure('Orange.TButton', background=c['primary'], foreground='white')
        style.map('Orange.TButton', background=[('active', c['primary'])])
        style.configure('Secondary.TButton', background=c['secondary_bg'], foreground=c['fg'])
        
        # Text widgets
        text_widgets = [self.sep_input, self.sep_output, self.input_a, self.input_b, self.host_input]
        for w in text_widgets:
            w.configure(bg=c['input_bg'], fg=c['input_fg'], insertbackground=c['primary'])
            
        # Treeviews
        style.configure("Treeview", background=c['input_bg'], foreground=c['input_fg'], fieldbackground=c['input_bg'])
        style.configure("Treeview.Heading", background=c['secondary_bg'], foreground=c['fg'])

    def create_separator_tab(self, parent):
        # SepRep v2.0: Vertical Flow Layout
        # Input -> Separator -> Options -> Progress -> Output
        
        main_frame = ttk.Frame(parent, padding=10)
        main_frame.pack(expand=True, fill='both')
        
        # 1. Input Section
        ttk.Label(main_frame, text="Input Text:", font=('Arial', 10, 'bold')).pack(anchor='w')
        self.sep_input = scrolledtext.ScrolledText(main_frame, height=6)
        self.sep_input.pack(fill='both', expand=True, pady=(0, 10))
        
        # 2. Separator Section
        sep_frame = ttk.Frame(main_frame)
        sep_frame.pack(fill='x', pady=5)
        ttk.Label(sep_frame, text="Separator:").pack(side='left')
        self.separator_var = tk.StringVar(value=',')
        tk.Entry(sep_frame, textvariable=self.separator_var, width=5).pack(side='left', padx=10)
        
        # 3. Options Section (SepRep v2.0)
        opt_frame = ttk.LabelFrame(main_frame, text="Reputation Checks")
        opt_frame.pack(fill='x', pady=5)
        
        self.var_vt = tk.BooleanVar(value=False)
        self.var_abuse = tk.BooleanVar(value=False)
        
        ttk.Checkbutton(opt_frame, text="VirusTotal", variable=self.var_vt).pack(side='left', padx=10)
        ttk.Checkbutton(opt_frame, text="AbuseIPDB", variable=self.var_abuse).pack(side='left', padx=10)
        
        # Proxy Settings Button (v1.3 Enhancement: Modal)
        ttk.Button(opt_frame, text="Proxy Settings", command=self.open_proxy_modal, style='Secondary.TButton').pack(side='right', padx=(5, 15))
        # API Settings Button
        ttk.Button(opt_frame, text="API Settings", command=self.open_api_modal, style='Secondary.TButton').pack(side='right', padx=5)
        
        # 4. Progress Section
        self.prog_frame = ttk.Frame(main_frame)
        self.prog_frame.pack(fill='x', pady=5)
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.prog_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill='x', side='left', expand=True)
        self.lbl_progress = ttk.Label(self.prog_frame, text="Idle")
        self.lbl_progress.pack(side='left', padx=5)
        
        # 5. Output Section
        ttk.Label(main_frame, text="Output Text:", font=('Arial', 10, 'bold')).pack(anchor='w', pady=(10, 0))
        self.sep_output = scrolledtext.ScrolledText(main_frame, height=8, state='disabled')
        self.sep_output.pack(fill='both', expand=True, pady=(5, 10))
        
        # Color Tags
        self.sep_output.tag_config('red', foreground='red')
        self.sep_output.tag_config('green', foreground='green')
        self.sep_output.tag_config('grey', foreground='grey')
        
        # Controls
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill='x')
        
        ttk.Button(btn_frame, text="Convert / Process", command=self.convert_text_threaded, style='Orange.TButton').pack(side='left', padx=(0, 10))
        ttk.Button(btn_frame, text="Clear", command=self.clear_separator, style='Secondary.TButton').pack(side='left')
        ttk.Button(btn_frame, text="Copy Output", command=self.copy_separator_output, style='Secondary.TButton').pack(side='right')
        
 

    def open_proxy_modal(self):
        # Modal Dialog
        dlg = tk.Toplevel(self.root)
        dlg.title("Proxy Settings")
        dlg.geometry("300x320")
        dlg.transient(self.root)
        dlg.grab_set()
        
        ttk.Label(dlg, text="Proxy Configuration", font=('Arial', 10, 'bold')).pack(pady=10)
        
        # Checkbox to Enable/Disable
        self.var_use_proxy = tk.BooleanVar(value=self.proxy_config.get('enabled', False))
        ttk.Checkbutton(dlg, text="Enable Proxy Connection", variable=self.var_use_proxy).pack(anchor='w', padx=20, pady=(0, 10))
        
        f = ttk.Frame(dlg, padding=10)
        f.pack(fill='both')
        
        ttk.Label(f, text="Host:").grid(row=0, column=0, pady=5)
        e_host = tk.Entry(f); e_host.grid(row=0, column=1, pady=5)
        e_host.insert(0, self.proxy_config.get('host', ''))
        
        ttk.Label(f, text="Port:").grid(row=1, column=0, pady=5)
        e_port = tk.Entry(f); e_port.grid(row=1, column=1, pady=5)
        e_port.insert(0, self.proxy_config.get('port', ''))

        ttk.Label(f, text="User:").grid(row=2, column=0, pady=5)
        e_user = tk.Entry(f); e_user.grid(row=2, column=1, pady=5)
        e_user.insert(0, self.proxy_config.get('username', ''))
        
        ttk.Label(f, text="Pass:").grid(row=3, column=0, pady=5)
        e_pass = tk.Entry(f, show="*"); e_pass.grid(row=3, column=1, pady=5)
        e_pass.insert(0, self.proxy_config.get('password', ''))
        
        # SSL Verification Check if needed? Spec implies "verify_ssl: false" default. Not critical for now.

        def save():
            self.proxy_config = {
                'enabled': self.var_use_proxy.get(),
                'host': e_host.get().strip(),
                'port': e_port.get().strip(),
                'username': e_user.get().strip(),
                'password': e_pass.get().strip()
            }
            # Update main config and persist
            self.custom_config['proxy'] = self.proxy_config
            self.save_settings()
            dlg.destroy()
            
        def test_connection():
            if not self.var_use_proxy.get():
                 messagebox.showinfo("Info", "Proxy is disabled. Testing direct connection (no proxy).")
                 # We could test direct connection, but user probably wants to test the PROXY.
                 # Let's assume test connection forces proxy use for the test even if disabled? 
                 # Or just warns. Let's warn.
                 # Actually user might want to test valid settings before enabling.
                 pass

            # Create a temporary config to test with
            temp_config = {
                'host': e_host.get().strip(),
                'port': e_port.get().strip(),
                'username': e_user.get().strip(),
                'password': e_pass.get().strip()
            }
            
            # If checking enabled, ensure host/port
            if not temp_config['host'] or not temp_config['port']:
                messagebox.showwarning("Missing Info", "Host and Port are required.")
                return

            try:
                # Use a lightweight checker instance
                checker = reputation.BaseChecker(proxy_settings=temp_config)
                # Test connection (using Google or a generic reliable host)
                # Using https to verify SSL/Connect through proxy
                resp = checker.session.get('https://www.google.com', timeout=10)
                if resp.status_code == 200:
                   messagebox.showinfo("Success", "Connection Verified Successfully (HTTPS)!")
                else:
                   messagebox.showwarning("Warning", f"Connected, but HTTP Status: {resp.status_code}")
            except Exception as e:
                messagebox.showerror("Connection Failed", f"Could not connect via proxy:\n{e}")

        # Buttons Frame
        btn_box = ttk.Frame(dlg)
        btn_box.pack(pady=10)
        
        ttk.Button(btn_box, text="Test Connection", command=test_connection, style='Secondary.TButton').pack(side='left', padx=5)
        ttk.Button(btn_box, text="Save", command=save, style='Orange.TButton').pack(side='left', padx=5)

    def open_api_modal(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("API Configuration")
        dlg.geometry("400x250")
        dlg.transient(self.root)
        dlg.grab_set()

        ttk.Label(dlg, text="API Keys", font=('Arial', 10, 'bold')).pack(pady=10)
        
        f = ttk.Frame(dlg, padding=10)
        f.pack(fill='both')
        
        keys = self.custom_config.get('api_keys', {})

        ttk.Label(f, text="VirusTotal API Key:").grid(row=0, column=0, pady=5, sticky='w')
        e_vt = tk.Entry(f, width=40, show="*"); e_vt.grid(row=1, column=0, pady=5)
        e_vt.insert(0, keys.get('vt_key', ''))

        ttk.Label(f, text="AbuseIPDB API Key:").grid(row=2, column=0, pady=5, sticky='w')
        e_abuse = tk.Entry(f, width=40, show="*"); e_abuse.grid(row=3, column=0, pady=5)
        e_abuse.insert(0, keys.get('abuse_key', ''))

        def save_api():
            self.custom_config['api_keys'] = {
                'vt_key': e_vt.get().strip(),
                'abuse_key': e_abuse.get().strip()
            }
            self.save_settings()
            dlg.destroy()
            messagebox.showinfo("Saved", "API Keys saved successfully.")

        ttk.Button(dlg, text="Save Keys", command=save_api, style='Orange.TButton').pack(pady=10)

    # --- SepRep Logic ---
    
    def convert_text_threaded(self):
        t = threading.Thread(target=self.convert_text)
        t.start()
        
    def convert_text(self):
        raw = self.sep_input.get("1.0", tk.END).strip()
        sep = self.separator_var.get() or ','
        
        if not raw: return

        # 2. Check if Rep Check is ON
        enable_vt = self.var_vt.get()
        enable_abuse = self.var_abuse.get()
        enable_rep = enable_vt or enable_abuse

        if enable_rep:
             # Strict splitting for Rep Check
             temp = raw.replace('\n', ' ').replace(',', ' ').replace('\t', ' ')
             tokens = temp.split()
        else:
             # Standard Mode
             temp = raw.replace('\n', ' ').replace(',', ' ').replace('\t', ' ')
             if ' ' not in temp and len(raw) > 1:
                tokens = list(raw)
             else:
                tokens = temp.split()
            
             res = sep.join(tokens)
             self.update_output(res)
             return

        # 3. SepRep v2.0 Execution
        self.update_output(f"Starting SepRep (VT={enable_vt}, Abuse={enable_abuse})...\n")
        self.progress_var.set(0)
        
        proxy_settings = None
        if self.proxy_config.get('host') and self.proxy_config.get('enabled', False):
            proxy_settings = self.proxy_config
            self.append_output("Proxy: ENABLED\n")
        else:
            self.append_output("Proxy: DISABLED (Direct Connection)\n")
            
        try:
            # Get API Keys
            api_keys = self.custom_config.get('api_keys', {})
            vt_key = api_keys.get('vt_key')
            abuse_key = api_keys.get('abuse_key')

            checker = reputation.ReputationChecker(vt_key=vt_key, abuse_key=abuse_key, proxy_settings=proxy_settings)
            
            total = len(tokens)
            processed = 0
            csv_rows = []
            
            # Header for CSV (v2.0)
            csv_rows.append([
                "Indicator", "Type", 
                "VT_Score", "VT_Verdict", 
                "Abuse_Score", "Abuse_Verdict", 
                "Country", "ISP", "Total_Reports", 
                "Final_Verdict", "Threat_Category"
            ])
            
            self.append_output(f"Processing {total} tokens...\n")

            for token in tokens:
                processed += 1
                
                # Update Progress
                perc = (processed / total) * 100
                self.progress_var.set(perc)
                self.lbl_progress.configure(text=f"Checking {processed} of {total}")
                
                # Check
                self.append_output(f"Checking {token}...")
                try:
                    res = checker.check_indicator(token, enable_vt=enable_vt, enable_abuse=enable_abuse)
                    self.append_output(" Done.\n")
                except Exception as e:
                    self.append_output(f" ERROR: {str(e)}\n")
                    # Should continue? Yes, try next token.
                    res = {'indicator': token, 'final_verdict': 'Error', 'type': 'Unknown'}

                # Extract Data
                ind_type = res.get('type', 'Unknown')
                final_verdict = res.get('final_verdict', 'Unknown')
                
                # VT Data
                vt_data = res.get('vt', {})
                vt_score = vt_data.get('malicious_score', '-')
                vt_verdict = vt_data.get('reputation', '-')
                vt_threat = vt_data.get('threat_category', 'Unknown')
                if "error" in vt_data: vt_verdict = f"Error: {vt_data.get('error')}"
                
                # AbuseIPDB Data
                ab_data = res.get('abuseip', {})
                ab_score = ab_data.get('score', '-')
                ab_verdict = ab_data.get('reputation', '-')
                ab_country = ab_data.get('country', '-')
                ab_isp = ab_data.get('isp', '-')
                ab_reports = ab_data.get('total_reports', '-')
                if "error" in ab_data: ab_verdict = f"Error: {ab_data.get('error')}"
                
                # CSV Row
                csv_rows.append([
                    token, ind_type, 
                    str(vt_score), vt_verdict, 
                    str(ab_score), ab_verdict, 
                    ab_country, ab_isp, str(ab_reports),
                    final_verdict, vt_threat
                ])
                
                # Update UI Output (Log style)
                row_str = f"Result: {token} | {final_verdict}"
                
                # Append detailed info or errors
                if "error" in vt_data:
                    row_str += f" | VT Error: {vt_data.get('error')}"
                else:
                    row_str += f" | VT:{vt_score}"
                    if vt_threat != 'Unknown':
                         row_str += f" ({vt_threat})"
                    
                if "error" in ab_data:
                    row_str += f" | AB Error: {ab_data.get('error')}"
                else:
                    row_str += f" | AB:{ab_score}"

                # Determine Color Tag
                tag = 'grey'
                if final_verdict == 'Malicious':
                    tag = 'red'
                elif final_verdict == 'Safe':
                    tag = 'green'
                
                self.append_output(row_str + "\n", tag=tag)
                
                # Rate Limit Delay (VT=15s, AbuseOnly=1s)
                if processed < total:
                    if enable_vt:
                        time.sleep(15)
                    else:
                        time.sleep(1) # Polite delay for AbuseIPDB

            self.lbl_progress.configure(text="Completed")
            
            # Auto-Export CSV (v2.0)
            self.auto_export_csv(csv_rows)
            
        except Exception as global_e:
            self.append_output(f"\nCRITICAL ERROR in Worker Thread: {global_e}\n")
            import traceback
            self.append_output(traceback.format_exc())
            self.lbl_progress.configure(text="Error")

    def auto_export_csv(self, rows):
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"reputation_results_{timestamp}.csv"
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerows(rows)
            # Notify user in output
            self.append_output(f"\n[INFO] Results auto-exported to: {os.path.abspath(filename)}\n")
        except Exception as e:
            self.append_output(f"\n[ERROR] Failed to export CSV: {e}\n")

    def update_output(self, text):
        self.sep_output.configure(state='normal')
        self.sep_output.delete("1.0", tk.END)
        self.sep_output.insert("1.0", text)
        self.sep_output.configure(state='disabled')

    def append_output(self, text, tag=None):
        self.sep_output.configure(state='normal')
        if tag:
            self.sep_output.insert(tk.END, text, (tag,))
        else:
            self.sep_output.insert(tk.END, text)
        self.sep_output.see(tk.END)
        self.sep_output.configure(state='disabled')

    def clear_separator(self):
        self.sep_input.delete("1.0", tk.END)
        self.sep_output.configure(state='normal')
        self.sep_output.delete("1.0", tk.END)
        self.sep_output.configure(state='disabled')
        if hasattr(self, 'progress_var'): self.progress_var.set(0)
        if hasattr(self, 'lbl_progress'): self.lbl_progress.configure(text="Idle")
    
    def copy_separator_output(self):
        s = self.sep_output.get("1.0", tk.END).strip()
        if s:
            self.root.clipboard_clear()
            self.root.clipboard_append(s)



    def create_hostsplit_tab(self, parent):
        # Spec 1.2.0: 3-Panel Layout (Input -> Actions -> Results)
        # We will use nested PanedWindows or Frames.
        # Main container: Horizontal PanedWindow
        
        self.host_paned = ttk.PanedWindow(parent, orient=tk.HORIZONTAL)
        self.host_paned.pack(fill='both', expand=True, padx=10, pady=10)

        # --- Panel 1: Input ---
        self.p1_frame = ttk.Labelframe(self.host_paned, text="Raw Host / IP Input")
        self.host_paned.add(self.p1_frame, weight=1)
        
        ttk.Label(self.p1_frame, text="Paste hostnames and IPs (comma or line separated):", font=('Arial', 9)).pack(anchor='w', padx=5, pady=2)
        
        self.host_input = scrolledtext.ScrolledText(self.p1_frame, height=20, width=30)
        self.host_input.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Placeholder Logic
        self.placeholder_text = "Paste hostnames and IPs here..."
        self.placeholder_color = 'grey'
        self.default_color = 'black'
        
        self.host_input.insert("1.0", self.placeholder_text)
        self.host_input.configure(foreground=self.placeholder_color)
        
        self.host_input.bind("<FocusIn>", self._on_host_focus_in)
        self.host_input.bind("<FocusOut>", self._on_host_focus_out)

        # Action: Clear
        ttk.Button(self.p1_frame, text="Clear", command=self.clear_hostsplit_v12, style='Secondary.TButton').pack(anchor='e', padx=5, pady=5)

        # --- Panel 2: Actions (Center) ---
        self.p2_frame = ttk.Frame(self.host_paned) # No border for cleaner look, or Labelframe if strict
        self.host_paned.add(self.p2_frame, weight=0) # Fixed width approx
        
        # Centering container for vertical stack
        action_container = ttk.Frame(self.p2_frame, padding=10)
        action_container.pack(fill='both', expand=True, anchor='center')
        
        ttk.Label(action_container, text="Actions", font=('Arial', 10, 'bold')).pack(pady=(0, 10))
        
        # Primary Actions
        # Normalization is now implicit in "Split Hosts / IPs"
        ttk.Button(action_container, text="Split Hosts / IPs", command=self.process_host_v12, style='Orange.TButton').pack(fill='x', pady=5)
        
        # Status Indicator
        self.norm_status_var = tk.StringVar(value="Ready")
        self.lbl_status = ttk.Label(action_container, textvariable=self.norm_status_var, foreground='gray', font=('Arial', 9, 'italic'))
        self.lbl_status.pack(pady=10)

        # Lookup Button (New v1.1)
        self.btn_lookup = ttk.Button(action_container, text="Lookup (DNS)", command=self.run_host_lookup_threaded, style='Secondary.TButton', state='disabled')
        self.btn_lookup.pack(fill='x', pady=5)
        
        # Secondary Actions
        ttk.Separator(action_container, orient='horizontal').pack(fill='x', pady=10)
        ttk.Button(action_container, text="Export JSON", command=self.export_host_json, style='Secondary.TButton').pack(fill='x', pady=5)
        ttk.Button(action_container, text="Export CSV", command=self.export_host_csv, style='Secondary.TButton').pack(fill='x', pady=5)

        # --- Panel 3: Results ---
        self.p3_frame = ttk.Labelframe(self.host_paned, text="Extracted Assets")
        self.host_paned.add(self.p3_frame, weight=2)
        
        # Treeview
        cols = ('type', 'host', 'ip', 'source', 'status')
        self.host_tree = ttk.Treeview(self.p3_frame, columns=cols, show='headings')
        self.host_tree.heading('type', text='Asset Type')
        self.host_tree.heading('host', text='Hostname')
        self.host_tree.heading('ip', text='IP Address')
        self.host_tree.heading('source', text='Source')
        self.host_tree.heading('status', text='Lookup Status')
        
        self.host_tree.column('type', width=80)
        self.host_tree.column('host', width=150)
        self.host_tree.column('ip', width=120)
        self.host_tree.column('source', width=80)
        self.host_tree.column('status', width=100)
        
        scrollbar = ttk.Scrollbar(self.p3_frame, orient="vertical", command=self.host_tree.yview)
        self.host_tree.configure(yscrollcommand=scrollbar.set)
        
        self.host_tree.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        scrollbar.pack(side='right', fill='y')

        # Logic State
        self.host_normalized_cache = []
        self.host_state = "raw" 

    def _on_host_focus_in(self, event):
        if self.host_input.get("1.0", tk.END).strip() == self.placeholder_text:
            self.host_input.delete("1.0", tk.END)
            self.host_input.configure(foreground=self.default_color)

    def _on_host_focus_out(self, event):
        if not self.host_input.get("1.0", tk.END).strip():
            self.host_input.insert("1.0", self.placeholder_text)
            self.host_input.configure(foreground=self.placeholder_color) 

    # --- HostSplit v1.2.0 Logic ---

    def clear_hostsplit_v12(self):
        self.host_input.delete("1.0", tk.END)
        self.norm_status_var.set("Input not normalized")
        self.lbl_status.configure(foreground='gray')
        self.host_state = "raw"
        self.host_normalized_cache = []
        self.btn_lookup.configure(state='disabled') # Disable lookup
        # Clear tree
        for item in self.host_tree.get_children():
            self.host_tree.delete(item)

    def normalize_host_v12(self):
        # 1. Get raw
        raw = self.host_input.get("1.0", tk.END)
        # 2. Call main.normalize_input_v12
        normalized = main.normalize_input_v12(raw)
        # 3. Cache
        self.host_normalized_cache = normalized
        self.host_state = "normalized"
        self.norm_status_var.set(f"Normalized: {len(normalized)} items")
        self.lbl_status.configure(foreground='green')
        return normalized

    def process_host_v12(self):
        # Implicitly normalize first (auto-normalize)
        self.normalize_host_v12()
             
        tokens = self.host_normalized_cache
        self.host_tree.delete(*self.host_tree.get_children())
        
        self.host_parsed_data = [] # Store for export
        
        for token in tokens:
            result = main.classify_asset(token)
            if not result: continue
            
            atype, host, ip = result
            
            # Insert into Tree
            self.host_tree.insert('', 'end', iid=str(len(self.host_parsed_data)), values=(atype, host, ip, "Derived", "Pending"))
            
            self.host_parsed_data.append({
                "type": atype,
                "hostname": host,
                "ip": ip,
                "source": "Derived",
                "status": "Pending",
                "id": str(len(self.host_parsed_data))
            })

        if self.host_parsed_data:
             self.btn_lookup.configure(state='normal')
        else:
             self.btn_lookup.configure(state='disabled')

    def run_host_lookup_threaded(self):
        self.btn_lookup.configure(state='disabled') # Prevent double click
        self.lbl_status.configure(text="Running DNS Lookup...", foreground='orange')
        t = threading.Thread(target=self.run_host_lookup)
        t.start()

    def run_host_lookup(self):
        try:
             engine = dns_engine.DNSLookupEngine()
             
             # Items to resolve
             to_resolve = self.host_parsed_data
             
             def callback(res_item):
                 # Update UI thread-safe
                 self.root.after(0, self.update_host_row, res_item)
                 
             results = engine.resolve_batch(to_resolve, callback=callback)
             
             # Update main data list with results
             # results is list of dicts. map back by ID or index
             self.host_parsed_data = results
             
             self.root.after(0, lambda: self.lbl_status.configure(text="Lookup Completed", foreground='green'))
             self.root.after(0, lambda: self.btn_lookup.configure(state='normal'))
             
        except Exception as e:
             print(f"DNS Error: {e}")
             self.root.after(0, lambda: self.lbl_status.configure(text="Lookup Error", foreground='red'))
             self.root.after(0, lambda: self.btn_lookup.configure(state='normal'))

    def update_host_row(self, item):
        # Find item in tree by iid (which we set to 'id' in process_host_v12)
        iid = item.get('id')
        if not iid: return
        
        # update values
        # values=(atype, host, ip, source, status)
        curr = self.host_tree.item(iid)['values']
        # curr is a tuple/list.
        
        # New values
        # type stays same
        # host updated
        # ip updated
        # source stays same
        # status updated
        
        new_vals = (
            curr[0], 
            item.get('hostname', ''), 
            item.get('ip', ''), 
            curr[3], 
            item.get('status', 'Unknown')
        )
        self.host_tree.item(iid, values=new_vals)

    def export_host_csv(self):
        if not getattr(self, 'host_parsed_data', None):
            messagebox.showinfo("Info", "No data to export.")
            return
            
        f = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if not f: return
        
        try:
            with open(f, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['type', 'hostname', 'ip', 'source', 'status']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(self.host_parsed_data)
            messagebox.showinfo("Success", "Export successful.")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {e}") 

    def copy_host_results(self):
        items = self.host_tree.get_children()
        rows = []
        for item in items:
            vals = self.host_tree.item(item)['values']
            rows.append(f"{vals[0]} | {vals[1]} | {vals[2]}")
        
        if rows:
            self.root.clipboard_clear()
            self.root.clipboard_append("\n".join(rows))
            messagebox.showinfo("Info", "Copied results to clipboard.")

    def export_host_csv(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile="host_split_results.csv")
        if file_path:
            items = self.host_tree.get_children()
            try:
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Type', 'Hostname', 'IP Address'])
                    for item in items:
                        writer.writerow(self.host_tree.item(item)['values'])
                messagebox.showinfo("Success", "Export successful.")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {e}")

    def export_host_json(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".json", initialfile="host_split_results.json")
        if file_path:
            items = self.host_tree.get_children()
            data = []
            for item in items:
                v = self.host_tree.item(item)['values']
                v = self.host_tree.item(item)['values']
                data.append({"type": v[0], "hostname": v[1], "ip": v[2], "source": v[3], "status": v[4]})
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
                messagebox.showinfo("Success", "Export successful.")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {e}")

    def create_comparator_tab(self, parent):

        
        # Inputs Frame
        inputs_frame = ttk.Frame(parent, padding=10)
        inputs_frame.pack(fill='both', expand=True)
        inputs_frame.columnconfigure(0, weight=1)
        inputs_frame.columnconfigure(1, weight=1)
        inputs_frame.rowconfigure(1, weight=1)
        
        # Input A Header
        head_a = ttk.Frame(inputs_frame)
        head_a.grid(row=0, column=0, sticky='ew', padx=5)
        ttk.Label(head_a, text="Input A", font=('Arial', 10, 'bold')).pack(side='left')
        self.count_a_var = tk.StringVar(value="(0 items)")
        ttk.Label(head_a, textvariable=self.count_a_var).pack(side='right')
        
        # Input B Header
        head_b = ttk.Frame(inputs_frame)
        head_b.grid(row=0, column=1, sticky='ew', padx=5)
        ttk.Label(head_b, text="Input B", font=('Arial', 10, 'bold')).pack(side='left')
        self.count_b_var = tk.StringVar(value="(0 items)")
        ttk.Label(head_b, textvariable=self.count_b_var).pack(side='right')
        
        # Text Areas
        self.input_a = scrolledtext.ScrolledText(inputs_frame, height=10, font=('Arial', 10))
        self.input_a.grid(row=1, column=0, sticky='nsew', padx=5, pady=5)
        self.input_a.bind('<KeyRelease>', lambda e: self.update_counts())
        
        self.input_b = scrolledtext.ScrolledText(inputs_frame, height=10, font=('Arial', 10))
        self.input_b.grid(row=1, column=1, sticky='nsew', padx=5, pady=5)
        self.input_b.bind('<KeyRelease>', lambda e: self.update_counts())
        
        # Upload Buttons
        ttk.Button(inputs_frame, text="Upload A (.txt/.csv)", command=lambda: self.upload_file(self.input_a), style='Secondary.TButton').grid(row=2, column=0, sticky='ew', padx=5, pady=(0, 10))
        ttk.Button(inputs_frame, text="Upload B (.txt/.csv)", command=lambda: self.upload_file(self.input_b), style='Secondary.TButton').grid(row=2, column=1, sticky='ew', padx=5, pady=(0, 10))

        # Main Buttons
        btns_frame = ttk.Frame(parent, padding=10)
        btns_frame.pack(fill='x')
        b_container = ttk.Frame(btns_frame)
        b_container.pack(anchor='center')
        
        ttk.Button(b_container, text="Normalize Inputs", command=self.normalize_inputs, style='Secondary.TButton').pack(side='left', padx=5)
        ttk.Button(b_container, text="Compare", command=self.compare_inputs, style='Orange.TButton').pack(side='left', padx=20) 
        ttk.Button(b_container, text="Reset", command=self.reset_comparator, style='Secondary.TButton').pack(side='left', padx=5)
        
        # FIX: Layout Ordering - Pack bottom elements first to ensure they are visible
        
        # Result Actions Footer (Pack Bottom)
        res_actions = ttk.Frame(parent, padding=10)
        res_actions.pack(side='bottom', fill='x', padx=10, pady=(0, 20))
        
        ttk.Button(res_actions, text="Copy All", command=self.copy_all_result, style='Secondary.TButton').pack(side='left', padx=5)
        ttk.Button(res_actions, text="Export CSV", command=self.export_csv, style='Secondary.TButton').pack(side='left', padx=5)
        ttk.Button(res_actions, text="Export JSON", command=self.export_json, style='Secondary.TButton').pack(side='left', padx=5)

        # Optimization Options (Pack Bottom, above Footer)
        opt_frame = ttk.Frame(parent, padding=10)
        opt_frame.pack(side='bottom', fill='x')
        
        self.var_mark_onboarded = tk.BooleanVar(value=False)
        # Bind the checkbox to update the view immediately if data exists
        ttk.Checkbutton(opt_frame, text="Mark Onboarded Status (Checks if present in both)", variable=self.var_mark_onboarded, command=self.refresh_view).pack(side='left', padx=10)

        # Results Tabs (Pack Remaining Space)
        self.res_notebook = ttk.Notebook(parent)
        self.res_notebook.pack(side='top', fill='both', expand=True, padx=10, pady=(0, 5)) 
        
        self.tab_common, self.tree_common = self.create_result_tree(self.res_notebook, "Common")
        self.tab_combined, self.tree_combined = self.create_result_tree(self.res_notebook, "Combined")
        self.tab_unique_a, self.tree_unique_a = self.create_result_tree(self.res_notebook, "Unique to A")
        self.tab_unique_b, self.tree_unique_b = self.create_result_tree(self.res_notebook, "Unique to B")

    def create_result_tree(self, parent_notebook, title):
        frame = ttk.Frame(parent_notebook)
        frame.pack(fill='both', expand=True)
        
        parent_notebook.add(frame, text=title)
        
        tree = ttk.Treeview(frame, show='headings')
        
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Initialize with correct columns based on default state
        mode = "detailed" if self.var_mark_onboarded.get() else "simple"
        self.configure_tree_columns(tree, mode)
        
        return frame, tree

    def upload_file(self, target_widget):
        file_path = filedialog.askopenfilename(filetypes=[("All Supported", "*.txt *.csv *.xlsx *.xls"), ("Excel Files", "*.xlsx *.xls"), ("Text/CSV", "*.txt *.csv")])
        if not file_path:
            return
            
        try:
            content = ""
            if file_path.lower().endswith(('.xlsx', '.xls')):
                # Excel Handler - Spec says: required_columns: ["hostname", "ip_or_hash"]
                df = pd.read_excel(file_path)
                # Normalize headers: lower, strip
                df.columns = [str(c).lower().strip().replace(' ', '_') for c in df.columns]

                # Map aliases to standard 'ip_or_hash' key
                rename_map = {}
                if 'ip_or_hash' not in df.columns:
                    if 'ipaddress' in df.columns:
                        rename_map['ipaddress'] = 'ip_or_hash'
                    elif 'hash' in df.columns:
                        rename_map['hash'] = 'ip_or_hash'
                    elif 'ip' in df.columns: # Helpful extra alias
                        rename_map['ip'] = 'ip_or_hash'
                
                if rename_map:
                    df.rename(columns=rename_map, inplace=True)
                
                required = ['hostname', 'ip_or_hash']
                # Check for required columns
                missing = [c for c in required if c not in df.columns]
                
                if missing:
                    # Fallback or Error? 
                    # Spec: "required_columns": ["hostname", "ip_or_hash"] (or aliases now)
                    messagebox.showwarning("Column Mismatch", f"Excel file missing columns: {missing}.\nExpected: hostname, ip_or_hash (or ipaddress, hash)")
                    return

                # Convert to text representation for the widget?
                # The widget is a Text widget (ScrolledText). We should populate it with a representation 
                # OR change the state logic to hold the DF separatedly.
                # Current Architecture relies on 'input_a' text widget content. 
                # We can serialize it as JSON or CSV in the text widget?
                # Or just Format: "hostname | ip_or_hash" per line?
                
                lines = []
                for _, row in df.iterrows():
                    h = str(row.get('hostname', '')).strip()
                    i = str(row.get('ip_or_hash', '')).strip()
                    if i:
                        lines.append(f"{h} | {i}")
                
                content = "\n".join(lines)
                
            else:
                # Text/CSV
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            
            target_widget.delete("1.0", tk.END)
            target_widget.insert("1.0", content)
            self.update_counts() # Trigger count update
            
        except Exception as e:
            messagebox.showerror("Upload Error", f"Failed to load file: {e}")

    def parse_input(self, text_content):
        # Helper to parse text widget content into key-value pairs (hostname, ip)
        # Supports: 
        # 1. "hostname | ip" (from our excel import)
        # 2. "ip" (raw list)
        # 3. "hostname, ip" etc via main.classify_asset
        
        lines = text_content.split('\n')
        parsed = []
        for line in lines:
            line = line.strip()
            if not line: continue
            
            # Use main.classify_asset for robust parsing
            try:
                res = main.classify_asset(line)
                if res:
                    type_str, val, ip = res
                    h_out = ""
                    i_out = ""
                    
                    if type_str == "IPv4":
                        i_out = ip
                    elif type_str == "Hostname":
                        h_out = val
                    elif type_str == "Derived":
                        h_out = val
                        i_out = ip
                    else:
                        i_out = line
                        
                    if i_out:
                        parsed.append({'hostname': h_out, 'ip_or_hash': i_out})
                    elif h_out:
                        parsed.append({'hostname': h_out, 'ip_or_hash': h_out}) 
                else:
                     parsed.append({'hostname': '', 'ip_or_hash': line})
            except Exception as e:
                print(f"Error parsing line '{line}': {e}")
                # Continue best effort
                parsed.append({'hostname': '', 'ip_or_hash': line})

        return parsed

    def normalize_inputs(self):
        # Parse and re-format inputs to standard "Hostname | IP" format
        raw_a = self.input_a.get("1.0", tk.END)
        parsed_a = self.parse_input(raw_a)
        lines_a = [f"{p['hostname']} | {p['ip_or_hash']}" if p['hostname'] else p['ip_or_hash'] for p in parsed_a]
        self.input_a.delete("1.0", tk.END)
        self.input_a.insert("1.0", "\n".join(lines_a))
        
        raw_b = self.input_b.get("1.0", tk.END)
        parsed_b = self.parse_input(raw_b)
        lines_b = [f"{p['hostname']} | {p['ip_or_hash']}" if p['hostname'] else p['ip_or_hash'] for p in parsed_b]
        self.input_b.delete("1.0", tk.END)
        self.input_b.insert("1.0", "\n".join(lines_b))
        
        self.update_counts()

    def compare_inputs(self):
        try:
            print("--- STARTING COMPARISON ---")
            # Get raw text
            raw_a = self.input_a.get("1.0", tk.END)
            raw_b = self.input_b.get("1.0", tk.END)
            print(f"Raw A length: {len(raw_a)} bytes")
            print(f"Raw B length: {len(raw_b)} bytes")
            
            # Parse into structured data
            list_a = self.parse_input(raw_a)
            list_b = self.parse_input(raw_b)
            print(f"Parsed List A: {len(list_a)} items")
            print(f"Parsed List B: {len(list_b)} items")
            if list_a: print(f"Sample A[0]: {list_a[0]}")
            if list_b: print(f"Sample B[0]: {list_b[0]}")
            
            check_onboarded = self.var_mark_onboarded.get()
            print(f"Check Onboarded: {check_onboarded}")
            
            # logic
            res = self.comp_engine.compare(list_a, list_b, check_onboarded=check_onboarded)
            print(f"Comparison Results - Common: {len(res['common'])}")
            print(f"Comparison Results - Unique A: {len(res['unique_to_a'])}")
            print(f"Comparison Results - Unique B: {len(res['unique_to_b'])}")
            
            # Combine all for the combined view
            res['combined'] = res['common'] + res['unique_to_a'] + res['unique_to_b']
            # Sort combined view to make it cohesive
            res['combined'].sort(key=lambda x: (x.get('hostname', '').lower(), x.get('ip_or_hash', '')))
            self.last_results = res # Cache for export
            
            # Populate Trees
            self.populate_tree(self.tree_common, res['common'])
            self.populate_tree(self.tree_combined, res['combined'])
            self.populate_tree(self.tree_unique_a, res['unique_to_a'])
            self.populate_tree(self.tree_unique_b, res['unique_to_b'])
            
            # Update tab titles with counts
            self.res_notebook.tab(self.tab_common, text=f"Common ({len(res['common'])})")
            self.res_notebook.tab(self.tab_combined, text=f"Combined ({len(res['combined'])})")
            self.res_notebook.tab(self.tab_unique_a, text=f"Unique to A ({len(res['unique_to_a'])})")
            self.res_notebook.tab(self.tab_unique_b, text=f"Unique to B ({len(res['unique_to_b'])})")
        except Exception as e:
            messagebox.showerror("Comparison Error", f"An error occurred during comparison:\n{e}")
            import traceback
            traceback.print_exc()

    def refresh_view(self):
        try:
            # Always update columns to reflect mode change immediately
            mode = "detailed" if self.var_mark_onboarded.get() else "simple"
            
            # Apply new column structure to all trees
            trees = [self.tree_common, self.tree_combined, self.tree_unique_a, self.tree_unique_b]
            for tree in trees:
                self.configure_tree_columns(tree, mode)

            # Trigger re-compare if data exists to populate rows with correct fields
            has_input = self.input_a.get("1.0", tk.END).strip() or self.input_b.get("1.0", tk.END).strip()
            
            if has_input:
                 self.compare_inputs()
            else:
                 # CRITICAL FIX: If no input, we MUST clear the trees because the columns have changed.
                 # Existing items (formatted for old columns) would be invalid/invisible.
                 for tree in trees:
                     tree.delete(*tree.get_children())
                     
        except Exception as e:
            print(f"Error in refresh_view: {e}")
            messagebox.showerror("Error", f"Failed to refresh view: {e}")

    def configure_tree_columns(self, tree, mode="detailed"):
        if mode == "detailed":
            cols = ('hostname', 'ip_or_hash', 'onboarded')
            tree.configure(columns=cols, show='headings')
            tree.heading('hostname', text='Hostname')
            tree.heading('ip_or_hash', text='IP / Hash')
            tree.heading('onboarded', text='Onboarded?')
            tree.column('hostname', width=150, stretch=True)
            tree.column('ip_or_hash', width=150, stretch=True)
            tree.column('onboarded', width=80, stretch=True)
        else:
            cols = ('val',)
            tree.configure(columns=cols, show='headings')
            tree.heading('val', text='Item Value')
            tree.column('val', width=400, stretch=True)

    def populate_tree(self, tree, data_list):
        tree.delete(*tree.get_children())
        
        mode = "detailed" if self.var_mark_onboarded.get() else "simple"
        
        # detailed cols: ('hostname', 'ip_or_hash', 'onboarded')
        # simple cols: ('val',)
        target_cols = ('hostname', 'ip_or_hash', 'onboarded') if mode == "detailed" else ('val',)
        
        # Only re-configure if columns differ (avoids resizing glitches on re-click)
        if str(tree['columns']) != str(target_cols):
             self.configure_tree_columns(tree, mode)
        
        for item in data_list:
            if mode == "detailed":
                tree.insert('', 'end', values=(
                    item.get('hostname', ''),
                    item.get('ip_or_hash', ''),
                    item.get('onboarded', '-')
                ))
            else:
                # Simple/Old view
                val = item.get('ip_or_hash', '')
                h = item.get('hostname', '')
                if h and h != val: # Only show host if different and present
                    val = f"{h} | {val}"
                tree.insert('', 'end', values=(val,))

    def update_counts(self):
        # Update labels with simple line counts for now
        # Ideally should parse, but that might be heavy on every keypress
        lines_a = len(self.input_a.get("1.0", tk.END).strip().split('\n'))
        lines_b = len(self.input_b.get("1.0", tk.END).strip().split('\n'))
        # Adjust for empty
        if not self.input_a.get("1.0", tk.END).strip(): lines_a = 0
        if not self.input_b.get("1.0", tk.END).strip(): lines_b = 0
        
        self.count_a_var.set(f"({lines_a} lines)")
        self.count_b_var.set(f"({lines_b} lines)")

    def reset_comparator(self):
        self.input_a.delete("1.0", tk.END)
        self.input_b.delete("1.0", tk.END)
        self.update_counts()
        self.tree_common.delete(*self.tree_common.get_children())
        self.tree_combined.delete(*self.tree_combined.get_children())
        self.tree_unique_a.delete(*self.tree_unique_a.get_children())
        self.tree_unique_b.delete(*self.tree_unique_b.get_children())
        self.res_notebook.tab(self.tab_common, text="Common")
        self.res_notebook.tab(self.tab_combined, text="Combined")
        self.res_notebook.tab(self.tab_unique_a, text="Unique to A")
        self.res_notebook.tab(self.tab_unique_b, text="Unique to B")

    def get_current_tree(self):
        current_tab_index = self.res_notebook.index(self.res_notebook.select())
        if current_tab_index == 0: return self.tree_common, "common"
        if current_tab_index == 1: return self.tree_combined, "combined"
        if current_tab_index == 2: return self.tree_unique_a, "unique_a"
        if current_tab_index == 3: return self.tree_unique_b, "unique_b"
        return None, None

    def copy_all_result(self):
        if not hasattr(self, 'last_results'): 
            messagebox.showinfo("Info", "No results to copy.")
            return

        lines = []
        for group, title in [("combined", "Combined"), ("common", "Common"), ("unique_to_a", "Unique to A"), ("unique_to_b", "Unique to B")]:
            items = self.last_results.get(group, [])
            if items:
                lines.append(f"--- {title} ---")
                for item in items:
                    h = item.get('hostname', '')
                    i = item.get('ip_or_hash', '')
                    o = item.get('onboarded', '-')
                    lines.append(f"{h} | {i} | Onboarded: {o}")
                lines.append("")
        
        full_text = "\n".join(lines)
        if full_text:
            self.root.clipboard_clear()
            self.root.clipboard_append(full_text)
            messagebox.showinfo("Success", "All results copied to clipboard.")
        else:
            messagebox.showinfo("Info", "No results found.")

    def export_csv(self):
        if not hasattr(self, 'last_results'): return
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not file_path: return
        
        try:
            tree, name = self.get_current_tree()
            if not tree: 
                 # Fallback to combined or common?
                 # If no tab selected? Unlikely.
                 name = "combined" 
            
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                # Spec Columns: hostname, ip_or_hash, comparison_result, onboarded
                writer.writerow(["hostname", "ip_or_hash", "comparison_result", "onboarded"])
                

                
                # Correct Logic: Use the 'name' from get_current_tree to fetch from last_results
                target_data = self.last_results.get(name, [])
                for item in target_data:
                    writer.writerow([
                        item.get('hostname', ''),
                        item.get('ip_or_hash', ''),
                        item.get('comparison_result', ''),
                        item.get('onboarded', 'No')
                    ])
            messagebox.showinfo("Success", "Export successful.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export: {e}")

    def export_json(self):
        tree, name = self.get_current_tree()
        if not tree: return
        file_path = filedialog.asksaveasfilename(defaultextension=".json", initialfile=f"{name}_results.json")
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    # Use logical data from last_results
                    target_data = self.last_results.get(name, [])
                    json.dump(target_data, f, indent=2)
                messagebox.showinfo("Success", "Export successful.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {e}")

    def on_closing(self):
        # Custom centered dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Quit")
        dialog.geometry("300x120")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Calculate center relative to parent
        self.root.update_idletasks() # Ensure geometry is up to date
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (300 // 2)
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - (120 // 2)
        dialog.geometry(f"+{x}+{y}")
        
        # Content
        msg_frame = ttk.Frame(dialog, padding=20)
        msg_frame.pack(fill='both', expand=True)
        
        ttk.Label(msg_frame, text="Do you want to quit?", anchor='center').pack(pady=(10, 20))
        
        btn_frame = ttk.Frame(msg_frame)
        btn_frame.pack()
        
        def confirm():
            dialog.destroy()
            self.root.destroy()
            
        def cancel():
            dialog.destroy()
            
        ttk.Button(btn_frame, text="OK", command=confirm, width=10).pack(side='left', padx=10)
        ttk.Button(btn_frame, text="Cancel", command=cancel, width=10).pack(side='left', padx=10)
        
        self.root.wait_window(dialog)






def main_gui():
    root = tk.Tk()
    app = SeparatorGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == '__main__':
    main_gui()
