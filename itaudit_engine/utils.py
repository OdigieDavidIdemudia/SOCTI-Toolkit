import logging
import sys
import json
import shutil
import os
from datetime import datetime
from pathlib import Path

class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno
        }
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_record)

def setup_logger(name: str = "domain_admission_engine", log_file: str = "audit.log", level=logging.INFO):
    """Function to setup logger with JSON formatting"""
    
    # JSON Formatter
    formatter = JsonFormatter('%(asctime)s')
    
    # File Handler
    handler = logging.FileHandler(log_file)        
    handler.setFormatter(formatter)
    
    # Console Handler
    console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(console_formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Clear existing handlers to avoid duplicates on reload
    if logger.hasHandlers():
        logger.handlers.clear()
        
    logger.addHandler(handler)
    logger.addHandler(console_handler)
    
    return logger

def get_resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    if getattr(sys, 'frozen', False):
        # PyInstaller creates a temp folder and stores path in _MEIPASS (onefile)
        # OR puts it in _internal (onedir)
        base_path = os.path.dirname(sys.executable)
        
        # Check for _internal folder (common in newer PyInstaller onedir)
        internal_path = os.path.join(base_path, '_internal')
        if os.path.exists(internal_path):
            base_path = internal_path
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))

    return os.path.join(base_path, relative_path)

def get_app_path():
    """ Get the absolute path to the application directory (where the exe is) """
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.abspath(".")

def archive_file(file_path: str, archive_dir: str = "archive"):
    """Archives a file to the specified directory with a timestamp."""
    try:
        os.makedirs(archive_dir, exist_ok=True)
        filename = os.path.basename(file_path)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        new_name = f"{timestamp}_{filename}"
        dest_path = os.path.join(archive_dir, new_name)
        shutil.copy2(file_path, dest_path)
        logger.info(f"Archived input file: {file_path} to {dest_path}")
    except Exception as e:
        logger.error(f"Failed to archive file {file_path}: {e}")

def cleanup_directory(directory_path: str, max_days: int = 30, max_files: int = 50):
    """
    Removes files from the directory that are older than max_days or if the total file count exceeds max_files.
    Deletes the oldest files first.
    """
    try:
        if not os.path.exists(directory_path):
            logger.info(f"Garbage Collection: Directory {directory_path} does not exist, skipping cleanup")
            return

        files = []
        try:
            for f in os.listdir(directory_path):
                full_path = os.path.join(directory_path, f)
                if os.path.isfile(full_path):
                    files.append(full_path)
        except Exception as e:
            logger.error(f"Garbage Collection: Failed to list directory {directory_path}: {e}")
            return
        
        if not files:
            logger.info(f"Garbage Collection: No files to clean in {directory_path}")
            return
            
        logger.info(f"Garbage Collection: Found {len(files)} files in {directory_path}")
        
        # Sort files by modification time (oldest first)
        try:
            files.sort(key=os.path.getmtime)
        except Exception as e:
            logger.error(f"Garbage Collection: Failed to sort files: {e}")
            return
        
        # 1. Cleanup by count
        files_removed_count = 0
        while len(files) > max_files:
            file_to_remove = files.pop(0)
            try:
                os.remove(file_to_remove)
                files_removed_count += 1
                logger.info(f"Garbage Collection: Removed excess file {os.path.basename(file_to_remove)}")
            except Exception as e:
                logger.warning(f"Garbage Collection: Failed to remove file {file_to_remove}: {e}")

        # 2. Cleanup by age
        current_time = datetime.now().timestamp()
        max_age_seconds = max_days * 86400
        
        for file_path in files:
            try:
                file_age = current_time - os.path.getmtime(file_path)
                if file_age > max_age_seconds:
                    try:
                        os.remove(file_path)
                        files_removed_count += 1
                        logger.info(f"Garbage Collection: Removed old file {os.path.basename(file_path)} (Age: {file_age/86400:.1f} days)")
                    except Exception as e:
                        logger.warning(f"Garbage Collection: Failed to remove file {file_path}: {e}")
            except Exception as e:
                logger.warning(f"Garbage Collection: Failed to check age of file {file_path}: {e}")
        
        if files_removed_count > 0:
            logger.info(f"Garbage Collection: Removed {files_removed_count} file(s) from {directory_path}")
        else:
            logger.info(f"Garbage Collection: No files needed to be removed from {directory_path}")
                    
    except Exception as e:
        logger.error(f"Garbage Collection: Unexpected error for {directory_path}: {e}")
        # Don't re-raise - cleanup failures should not break the pipeline

logger = setup_logger()
