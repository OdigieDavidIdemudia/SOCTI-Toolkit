import customtkinter as ctk
from tkinter import filedialog, messagebox
from tkinterdnd2 import TkinterDnD, DND_FILES
import threading
import os
from PIL import Image
from .main import process_pipeline
from .utils import logger
import logging
from .theme import GT_THEME

class LogHandler(logging.Handler):
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget

    def emit(self, record):
        msg = self.format(record)
        self.text_widget.configure(state='normal')
        self.text_widget.insert('end', msg + '\n')
        self.text_widget.see('end')
        self.text_widget.configure(state='disabled')


import math

class LoadingAnimation(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        
        # Resolve background color
        bg_color = master.cget("fg_color")
        if isinstance(bg_color, (list, tuple)):
            # Default to the mode, but canvas needs a single color.
            # We'll set it dynamically or just pick one and update on theme change.
            # For now, let's grab the current mode's color.
            mode = ctk.get_appearance_mode()
            bg_color = bg_color[1] if mode == "Dark" else bg_color[0]
            
        self.canvas = ctk.CTkCanvas(self, width=200, height=100, bg=bg_color, highlightthickness=0)
        self.canvas.pack()
        self.dots = []
        self.running = False
        
        # Create 3 dots
        primary_color = GT_THEME['themes']['light']['colors']['primary']
        for i in range(3):
            x = 70 + i * 30
            y = 50
            dot = self.canvas.create_oval(x-5, y-5, x+5, y+5, fill=primary_color, outline="")
            self.dots.append(dot)
            
    def start(self):
        self.running = True
        self.animate(0)
        
    def stop(self):
        self.running = False
        
    def animate(self, step):
        if not self.running:
            return
            
        # Wave animation
        for i, dot in enumerate(self.dots):
            offset = (step + i * 10) % 60
            y = 50 - 15 * math.sin(offset * math.pi / 30) if offset < 30 else 50
            
            x = 70 + i * 30
            self.canvas.coords(dot, x-5, y-5, x+5, y+5)
            
        self.after(20, lambda: self.animate(step + 1))

class App(ctk.CTk, TkinterDnD.DnDWrapper):
    def __init__(self):
        super().__init__()
        self.TkdndVersion = TkinterDnD._require(self)

        # Theme Configuration
        self.light_theme = GT_THEME['themes']['light']
        self.dark_theme = GT_THEME['themes']['dark']
        
        # Helper to get color tuple (light, dark)
        def c(key, subkey=None):
            l = self.light_theme['colors'][key]
            d = self.dark_theme['colors'][key]
            if subkey:
                l = self.light_theme['components'][key][subkey]
                d = self.dark_theme['components'][key][subkey]
            return (l, d)

        # Window Setup
        self.title(GT_THEME['app_name'])
        self.geometry("900x700")
        
        # Set Appearance Mode based on config
        default_mode = GT_THEME['theme_toggle']['default_mode']
        ctk.set_appearance_mode("Light" if default_mode == "light" else "Dark")
        
        # Main Background
        self.configure(fg_color=c('background'))

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)

        # --- Header Section ---
        self.header_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.header_frame.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")
        
        # Logo
        try:
            from .utils import get_resource_path
            logo_path = get_resource_path(os.path.join("src", "assets", "logo.png"))
            if os.path.exists(logo_path):
                pil_image = Image.open(logo_path)
                self.logo_image = ctk.CTkImage(light_image=pil_image, dark_image=pil_image, size=(50, 50))
                self.logo_label = ctk.CTkLabel(self.header_frame, image=self.logo_image, text="")
                self.logo_label.pack(side="left", padx=(0, 15))
                
            # Set Window Icon
            icon_path = get_resource_path(os.path.join("src", "assets", "icon.ico"))
            if os.path.exists(icon_path):
                self.iconbitmap(icon_path)
                
        except Exception as e:
            logger.warning(f"Could not load logo/icon: {e}")

        # Title
        self.title_label = ctk.CTkLabel(
            self.header_frame, 
            text=GT_THEME['app_name'], 
            font=(self.light_theme['typography']['font_family'], 28, "bold"),
            text_color=c('text_primary')
        )
        self.title_label.pack(side="left")
        
        # Theme Toggle
        if GT_THEME['theme_toggle']['enabled']:
            self.theme_switch = ctk.CTkSwitch(
                self.header_frame, 
                text="Dark Mode", 
                command=self.toggle_theme,
                progress_color=self.light_theme['colors']['primary'],
                text_color=c('text_primary')
            )
            self.theme_switch.pack(side="right")
            if default_mode == "dark":
                self.theme_switch.select()

        # --- Input Section ---
        self.input_frame = ctk.CTkFrame(
            self, 
            fg_color=c('surface'),
            corner_radius=GT_THEME['layout']['rounded_corners'],
            border_width=1,
            border_color=c('border')
        )
        self.input_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        self.input_frame.grid_columnconfigure(1, weight=1)

        # Common Style for Inputs
        entry_config = {
            "fg_color": c('input_bg'),
            "border_color": c('input_border'),
            "text_color": c('text_primary'),
            "height": 40,
            "corner_radius": 4
        }
        
        btn_config = {
            "fg_color": c('surface'),
            "text_color": c('text_primary'),
            "border_color": c('border'),
            "border_width": 1,
            "hover_color": c('table_row_hover'),
            "height": 40
        }

        # System Joined Input
        self.joined_label = ctk.CTkLabel(self.input_frame, text="System Joined CSV:", text_color=c('text_primary'))
        self.joined_label.grid(row=0, column=0, padx=15, pady=15, sticky="w")
        
        self.joined_entry = ctk.CTkEntry(self.input_frame, placeholder_text="Select file...", **entry_config)
        self.joined_entry.grid(row=0, column=1, padx=10, pady=15, sticky="ew")
        
        # Enable Drag and Drop
        self.joined_entry._entry.drop_target_register(DND_FILES)
        self.joined_entry._entry.dnd_bind('<<Drop>>', lambda e: self.on_drop(e, self.joined_entry))
        
        self.joined_btn = ctk.CTkButton(self.input_frame, text="Browse", command=self.browse_joined, **btn_config)
        self.joined_btn.grid(row=0, column=2, padx=15, pady=15)

        # Host Inventory Input
        self.inventory_label = ctk.CTkLabel(self.input_frame, text="Host Inventory CSV:", text_color=c('text_primary'))
        self.inventory_label.grid(row=1, column=0, padx=15, pady=15, sticky="w")
        
        self.inventory_entry = ctk.CTkEntry(self.input_frame, placeholder_text="Select file...", **entry_config)
        self.inventory_entry.grid(row=1, column=1, padx=10, pady=15, sticky="ew")

        # Enable Drag and Drop
        self.inventory_entry._entry.drop_target_register(DND_FILES)
        self.inventory_entry._entry.dnd_bind('<<Drop>>', lambda e: self.on_drop(e, self.inventory_entry))
        
        self.inventory_btn = ctk.CTkButton(self.input_frame, text="Browse", command=self.browse_inventory, **btn_config)
        self.inventory_btn.grid(row=1, column=2, padx=15, pady=15)

        # --- Action Section ---
        self.button_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.button_frame.grid(row=2, column=0, padx=20, pady=20, sticky="ew")
        self.button_frame.grid_columnconfigure((0, 1), weight=1)

        self.generate_btn = ctk.CTkButton(
            self.button_frame, 
            text="Generate Report", 
            command=self.start_generation, 
            height=50, 
            font=(self.light_theme['typography']['font_family'], 18, "bold"),
            fg_color=self.light_theme['colors']['primary'], 
            hover_color=self.light_theme['colors']['primary_hover'],
            text_color="#FFFFFF"
        )
        self.generate_btn.grid(row=0, column=0, padx=(0, 10), sticky="ew")

        self.reset_btn = ctk.CTkButton(
            self.button_frame,
            text="Reset",
            command=self.reset_app,
            height=50,
            font=(self.light_theme['typography']['font_family'], 18, "bold"),
            fg_color="transparent",
            border_width=2,
            border_color=self.light_theme['colors']['primary'],
            text_color=c('text_primary'),
            hover_color=c('table_row_hover')
        )
        self.reset_btn.grid(row=0, column=1, padx=(10, 0), sticky="ew")

        # --- Status Section ---
        # Log box exists but is hidden initially
        self.log_box = ctk.CTkTextbox(
            self, 
            state='disabled',
            fg_color=c('surface'),
            text_color=c('text_primary'),
            corner_radius=4,
            border_width=1,
            border_color=c('border')
        )
        # self.log_box.grid(...) -> Don't grid it by default!
        
        # Loading Animation
        self.loading_frame = LoadingAnimation(self)
        
        # --- Result Section ---
        self.open_btn = ctk.CTkButton(
            self, 
            text="Open Report Folder", 
            command=self.open_report_folder, 
            state="disabled",
            fg_color=c('surface'),
            text_color=c('text_primary'),
            border_color=c('border'),
            border_width=1,
            hover_color=c('table_row_hover')
        )
        self.open_btn.grid(row=4, column=0, padx=20, pady=20)

        # Setup Logging
        log_handler = LogHandler(self.log_box)
        log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(log_handler)

    def toggle_theme(self):
        # Add a small delay to allow the switch animation to start/finish smoothly
        # before the heavy theme change operation occurs.
        self.after(200, self._apply_theme_change)

    def _apply_theme_change(self):
        if self.theme_switch.get() == 1:
            ctk.set_appearance_mode("Dark")
            self.loading_frame.canvas.configure(bg=self.dark_theme['colors']['background'])
        else:
            ctk.set_appearance_mode("Light")
            self.loading_frame.canvas.configure(bg=self.light_theme['colors']['background'])

    def browse_joined(self):
        filename = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
        if filename:
            self.joined_entry.delete(0, "end")
            self.joined_entry.insert(0, filename)

    def browse_inventory(self):
        filename = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
        if filename:
            self.inventory_entry.delete(0, "end")
            self.inventory_entry.insert(0, filename)

    def start_generation(self):
        joined_path = self.joined_entry.get()
        inventory_path = self.inventory_entry.get()

        if not joined_path or not inventory_path:
            messagebox.showerror("Error", "Please select both CSV files.")
            return

        # Prepare UI for processing
        self.generate_btn.configure(state="disabled")
        self.reset_btn.configure(state="disabled")
        self.joined_entry.configure(state="disabled")
        self.inventory_entry.configure(state="disabled")
        self.open_btn.grid_forget() # Hide open button if visible
        
        # Hide standard log box if it was visible
        self.log_box.grid_forget()
        
        # Show Loading Animation
        self.loading_frame.grid(row=3, column=0, padx=20, pady=20, sticky="")
        self.loading_frame.start()
        
        # Clear log box content for new run
        self.log_box.configure(state='normal')
        self.log_box.delete('1.0', 'end')
        self.log_box.configure(state='disabled')

        thread = threading.Thread(target=self.run_pipeline, args=(joined_path, inventory_path))
        thread.start()

    def run_pipeline(self, joined_path, inventory_path):
        try:
            output_file = process_pipeline(joined_path, inventory_path)
            self.after(0, lambda: self.on_success(output_file))
        except Exception as e:
            self.after(0, lambda: self.on_error(str(e)))

    def on_success(self, output_file):
        # Stop and Hide Animation
        self.loading_frame.stop()
        self.loading_frame.grid_forget()
        
        messagebox.showinfo("Success", f"Report generated successfully!\n{output_file}")
        
        # Restore UI
        self.generate_btn.configure(state="normal")
        self.reset_btn.configure(state="normal")
        self.joined_entry.configure(state="normal")
        self.inventory_entry.configure(state="normal")
        
        self.open_btn.configure(state="normal")
        self.open_btn.grid(row=4, column=0, padx=20, pady=20)
        
        self.last_output_file = output_file

    def on_error(self, error_msg):
        # Stop Animation
        self.loading_frame.stop()
        self.loading_frame.grid_forget()
        
        # Show Error and Logs
        messagebox.showerror("Error", f"An error occurred:\n{error_msg}")
        self.log_box.grid(row=3, column=0, padx=20, pady=10, sticky="nsew")
        
        # Restore UI
        self.generate_btn.configure(state="normal")
        self.reset_btn.configure(state="normal")
        self.joined_entry.configure(state="normal")
        self.inventory_entry.configure(state="normal")

    def open_report_folder(self):
        if hasattr(self, 'last_output_file'):
            folder = os.path.dirname(self.last_output_file)
            os.startfile(folder)

    def on_drop(self, event, entry_widget):
        file_path = event.data
        if file_path.startswith('{') and file_path.endswith('}'):
            file_path = file_path[1:-1]
        entry_widget.delete(0, 'end')
        entry_widget.insert(0, file_path)

    def reset_app(self):
        self.joined_entry.delete(0, 'end')
        self.inventory_entry.delete(0, 'end')
        self.log_box.configure(state='normal')
        self.log_box.delete('1.0', 'end')
        self.log_box.configure(state='disabled')
        self.log_box.grid_forget() # Hide logs
        self.generate_btn.configure(state="normal")
        self.open_btn.configure(state="disabled")
        self.loading_frame.stop()
        self.loading_frame.grid_forget()

def run_gui():
    app = App()
    app.mainloop()
