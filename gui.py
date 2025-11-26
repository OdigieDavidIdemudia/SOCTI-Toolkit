#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, scrolledtext
import main


class SeparatorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SepX - Separator Tool")
        self.root.geometry("600x500")
        self.root.resizable(True, True)
        
        # Color scheme - Orange and Grey
        self.bg_color = "#2b2b2b"  # Dark grey background
        self.fg_color = "#e0e0e0"  # Light grey text
        self.orange_primary = "#ff8c42"  # Primary orange
        self.orange_secondary = "#ff6b35"  # Secondary orange
        self.grey_light = "#4a4a4a"  # Light grey for inputs
        self.grey_medium = "#3a3a3a"  # Medium grey
        
        # Configure root background
        self.root.configure(bg=self.bg_color)
        
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Custom styles
        style.configure('Main.TFrame', background=self.bg_color)
        style.configure('Title.TLabel', 
                       background=self.bg_color, 
                       foreground=self.orange_primary,
                       font=('Arial', 20, 'bold'))
        style.configure('Label.TLabel', 
                       background=self.bg_color, 
                       foreground=self.fg_color,
                       font=('Arial', 10, 'bold'))
        style.configure('Orange.TButton',
                       background=self.orange_primary,
                       foreground='white',
                       borderwidth=0,
                       focuscolor='none',
                       font=('Arial', 10, 'bold'))
        style.map('Orange.TButton',
                 background=[('active', self.orange_secondary)])
        
        # Main frame
        main_frame = ttk.Frame(root, padding="10", style='Main.TFrame')
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)
        main_frame.rowconfigure(3, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="SepX", style='Title.TLabel')
        title_label.grid(row=0, column=0, pady=(0, 10))
        
        # Input section
        input_label = ttk.Label(main_frame, text="Input Text:", style='Label.TLabel')
        input_label.grid(row=0, column=0, sticky=tk.W, pady=(10, 5))
        
        self.input_text = scrolledtext.ScrolledText(main_frame, height=8, 
                                                    wrap=tk.WORD, 
                                                    font=('Arial', 10),
                                                    bg=self.grey_light,
                                                    fg=self.fg_color,
                                                    insertbackground=self.orange_primary,
                                                    selectbackground=self.orange_primary,
                                                    selectforeground='white')
        self.input_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), 
                            pady=(0, 10))
        
        # Separator input
        separator_frame = ttk.Frame(main_frame, style='Main.TFrame')
        separator_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=10)
        
        separator_label = ttk.Label(separator_frame, text="Separator:", style='Label.TLabel')
        separator_label.pack(side=tk.LEFT, padx=(0, 10))
        
        self.separator_var = tk.StringVar(value=',')
        self.separator_entry = tk.Entry(separator_frame, 
                                        textvariable=self.separator_var, 
                                        width=10,
                                        bg=self.grey_light,
                                        fg=self.fg_color,
                                        insertbackground=self.orange_primary,
                                        selectbackground=self.orange_primary,
                                        selectforeground='white',
                                        font=('Arial', 10),
                                        relief=tk.FLAT,
                                        borderwidth=2)
        self.separator_entry.pack(side=tk.LEFT, padx=(0, 20))
        
        # Convert button
        self.convert_btn = ttk.Button(separator_frame, text="Convert", 
                                     command=self.convert_text,
                                     style='Orange.TButton')
        self.convert_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Clear button
        self.clear_btn = ttk.Button(separator_frame, text="Clear All", 
                                   command=self.clear_all,
                                   style='Orange.TButton')
        self.clear_btn.pack(side=tk.LEFT)
        
        # Output section
        output_label = ttk.Label(main_frame, text="Output Text:", style='Label.TLabel')
        output_label.grid(row=2, column=0, sticky=tk.W, pady=(60, 5))
        
        self.output_text = scrolledtext.ScrolledText(main_frame, height=8, 
                                                     wrap=tk.WORD, 
                                                     font=('Arial', 10),
                                                     bg=self.grey_light,
                                                     fg=self.fg_color,
                                                     insertbackground=self.orange_primary,
                                                     selectbackground=self.orange_primary,
                                                     selectforeground='white',
                                                     state='disabled')
        self.output_text.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Copy button
        copy_frame = ttk.Frame(main_frame, style='Main.TFrame')
        copy_frame.grid(row=4, column=0, sticky=tk.E, pady=(10, 0))
        
        self.copy_btn = ttk.Button(copy_frame, text="Copy Output", 
                                  command=self.copy_output,
                                  style='Orange.TButton')
        self.copy_btn.pack(side=tk.RIGHT)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = tk.Label(main_frame, textvariable=self.status_var, 
                              relief=tk.FLAT, anchor=tk.W,
                              bg=self.grey_medium,
                              fg=self.orange_primary,
                              font=('Arial', 9),
                              padx=5, pady=3)
        status_bar.grid(row=5, column=0, sticky=(tk.W, tk.E), pady=(10, 0))
        
        # Bind Enter key to convert
        self.root.bind('<Return>', lambda e: self.convert_text())
        
    def convert_text(self):
        """Convert input text with separator."""
        input_str = self.input_text.get("1.0", tk.END).strip()
        separator = self.separator_var.get()
        
        if not input_str:
            self.status_var.set("Error: Please enter some text")
            return
        
        if not separator:
            separator = ','
            self.separator_var.set(',')
        
        # Use the main module's function
        result = main.add_separator(input_str, separator)
        
        # Update output
        self.output_text.config(state='normal')
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert("1.0", result)
        self.output_text.config(state='disabled')
        
        self.status_var.set(f"Conversion complete! Used separator: '{separator}'")
    
    def clear_all(self):
        """Clear all text fields."""
        self.input_text.delete("1.0", tk.END)
        self.output_text.config(state='normal')
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state='disabled')
        self.separator_var.set(',')
        self.status_var.set("Cleared all fields")
    
    def copy_output(self):
        """Copy output text to clipboard."""
        output_str = self.output_text.get("1.0", tk.END).strip()
        if output_str:
            self.root.clipboard_clear()
            self.root.clipboard_append(output_str)
            self.status_var.set("Output copied to clipboard!")
        else:
            self.status_var.set("Error: No output to copy")


def main_gui():
    root = tk.Tk()
    app = SeparatorGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main_gui()
