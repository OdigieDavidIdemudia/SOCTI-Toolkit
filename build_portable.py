import os
import shutil
import subprocess
import zipfile
import sys

def build_executable():
    """Runs PyInstaller to build the executable."""
    print("Starting PyInstaller build...")
    
    # PyInstaller arguments
    args = [
        'gui.py',  # Entry point
        '--name=SOCTI_Toolkit',
        '--onefile', # Single executable
        '--noconsole', # No console window
        '--clean',
        '--add-data=assets;assets', # Include assets folder
        '--add-data=settings.json.example;.' # Include example settings
        # Hidden imports might be needed, but usually PyInstaller finds them.
        # If needed: '--hidden-import=PIL', '--hidden-import=tkinter'
    ]
    
    # Run PyInstaller
    # We use subprocess to run it as a command ensuring it uses the installed pyinstaller
    try:
        subprocess.check_call([sys.executable, '-m', 'PyInstaller'] + args)
        print("PyInstaller build completed successfully.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"PyInstaller failed with error: {e}")
        return False

def create_zip():
    """Creates a portable ZIP file containing the executable and necessary files."""
    print("Creating portable ZIP...")
    
    dist_dir = 'dist'
    exe_name = 'SOCTI_Toolkit.exe'
    zip_name = 'socti-toolkit.zip'
    
    exe_path = os.path.join(dist_dir, exe_name)
    
    if not os.path.exists(exe_path):
        print(f"Error: Executable not found at {exe_path}")
        return False
        
    # specific files to include in the root of the zip alongside the exe if needed
    # Since we used --onefile, the exe should be self-contained for python libs.
    # We might want to include the README or License if they exist.
    
    files_to_include = [
        (exe_path, exe_name),
        ('README.md', 'README.md'),
        ('LICENSE', 'LICENSE'),
        ('settings.json.example', 'settings.json.example')
    ]

    try:
        with zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for src, arcname in files_to_include:
                if os.path.exists(src):
                    print(f"Adding {src} as {arcname}")
                    zipf.write(src, arcname)
                else:
                    print(f"Warning: {src} not found, skipping.")
        
        print(f"Portable ZIP created: {zip_name}")
        return True
    except Exception as e:
        print(f"Failed to create ZIP: {e}")
        return False

def main():
    # 1. Build
    if not build_executable():
        sys.exit(1)
        
    # 2. Zip
    if not create_zip():
        sys.exit(1)
        
    print("\nDraft Process Completed Successfully!")

if __name__ == "__main__":
    main()
