import os
import sys
import zipfile
import magic
import hashlib
import tempfile
import shutil
import subprocess
from pathlib import Path
import argparse
import logging
from typing import Tuple, List, Dict

class SafeZipExplorer:
    def __init__(self, sandbox_path: str = None):
        self.sandbox_path = sandbox_path or tempfile.mkdtemp(prefix="safe_zip_sandbox_")
        self.logger = self._setup_logger()
        
    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger('SafeZipExplorer')
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def _create_sandbox(self) -> str:
        """Creates an isolated sandbox directory"""
        os.makedirs(self.sandbox_path, exist_ok=True)
        self.logger.info(f"Created sandbox at: {self.sandbox_path}")
        return self.sandbox_path

    def _cleanup_sandbox(self):
        """Removes the sandbox directory and all its contents"""
        try:
            shutil.rmtree(self.sandbox_path)
            self.logger.info("Sandbox cleaned up successfully")
        except Exception as e:
            self.logger.error(f"Error cleaning up sandbox: {e}")

    def _scan_file_threats(self, file_path: str) -> Dict[str, bool]:
        """
        Scans a file for potential threats
        Returns a dictionary of threat indicators
        """
        threats = {
            "suspicious_extension": False,
            "executable_content": False,
            "excessive_size": False,
            "suspicious_magic_bytes": False
        }

        # Check file extension
        suspicious_extensions = {'.exe', '.dll', '.bat', '.cmd', '.vbs', '.js'}
        if Path(file_path).suffix.lower() in suspicious_extensions:
            threats["suspicious_extension"] = True

        # Check file size (>100MB is suspicious)
        if os.path.getsize(file_path) > 100_000_000:
            threats["excessive_size"] = True

        # Check file type using magic numbers
        mime = magic.Magic(mime=True)
        file_type = mime.from_file(file_path)
        suspicious_types = {'application/x-dosexec', 'application/x-executable'}
        if file_type in suspicious_types:
            threats["executable_content"] = True
            threats["suspicious_magic_bytes"] = True

        return threats

    def analyze_zip(self, zip_path: str) -> Tuple[List[str], Dict[str, List[str]]]:
        """
        Analyzes a zip file for contents and potential threats
        Returns a tuple of (file_list, threats)
        """
        if not os.path.exists(zip_path):
            raise FileNotFoundError(f"Zip file not found: {zip_path}")

        sandbox_dir = self._create_sandbox()
        file_list = []
        threats = {"suspicious_files": [], "error_files": []}

        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                # First, list all files without extracting
                file_list = zip_ref.namelist()
                
                # Check for path traversal attempts
                for file_path in file_list:
                    if file_path.startswith('/') or '..' in file_path:
                        threats["suspicious_files"].append(f"Path traversal attempt: {file_path}")
                        continue

                # Extract files to sandbox
                zip_ref.extractall(sandbox_dir)

                # Scan each extracted file
                for file_name in file_list:
                    full_path = os.path.join(sandbox_dir, file_name)
                    if os.path.isfile(full_path):
                        try:
                            file_threats = self._scan_file_threats(full_path)
                            if any(file_threats.values()):
                                threats["suspicious_files"].append(f"{file_name}: {file_threats}")
                        except Exception as e:
                            threats["error_files"].append(f"{file_name}: {str(e)}")

        except Exception as e:
            self.logger.error(f"Error processing zip file: {e}")
            raise

        finally:
            self._cleanup_sandbox()

        return file_list, threats

def main():
    parser = argparse.ArgumentParser(description='Safely explore zip files in a sandbox environment')
    parser.add_argument('zip_path', help='Path to the zip file to analyze')
    parser.add_argument('--extract-path', help='Path to extract files if no threats found')
    args = parser.parse_args()

    explorer = SafeZipExplorer()
    
    try:
        file_list, threats = explorer.analyze_zip(args.zip_path)
        
        print("\nFiles in zip:")
        for file in file_list:
            print(f"- {file}")

        if threats["suspicious_files"] or threats["error_files"]:
            print("\nPotential threats detected:")
            for file in threats["suspicious_files"]:
                print(f"WARNING: {file}")
            for file in threats["error_files"]:
                print(f"ERROR: {file}")
                
            user_input = input("\nThreats detected. Do you want to proceed with extraction? (yes/no): ")
            if user_input.lower() != 'yes':
                print("Extraction cancelled.")
                return
                
        if args.extract_path:
            with zipfile.ZipFile(args.zip_path, 'r') as zip_ref:
                zip_ref.extractall(args.extract_path)
            print(f"\nFiles extracted to: {args.extract_path}")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()