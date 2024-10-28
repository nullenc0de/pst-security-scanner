#!/usr/bin/env python3
"""
PST File Scanner for Sensitive Information
This script scans Microsoft Outlook PST files for potentially sensitive information
using pattern matching and keyword detection.

Dependencies:
- readpst (pst-utils package)
- python-magic (optional, for file type verification)
"""

import subprocess
import re
import sys
import os
import logging
from datetime import datetime
from typing import List, Set, Dict, Optional, Tuple
from dataclasses import dataclass
import multiprocessing as mp
from pathlib import Path
import json
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

@dataclass
class SensitiveMatch:
    """Data class to store information about detected sensitive content."""
    email_id: str
    subject: str
    matched_keywords: Set[str]
    context: str
    timestamp: str

class KeywordManager:
    """Manages keyword patterns and categories for sensitive information detection."""
    
    def __init__(self, custom_keywords_file: Optional[str] = None):
        self.keyword_categories: Dict[str, List[str]] = {
            'authentication': [
                r'password', r'passwd', r'credentials', r'api[_\s]?key',
                r'secret[_\s]?key', r'token', r'auth'
            ],
            'personal_info': [
                r'ssn', r'social[_\s]?security', r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b',
                r'date[_\s]?of[_\s]?birth', r'driver[_\s]?license'
            ],
            'financial': [
                r'credit[_\s]?card', r'cvv', r'iban', r'account[_\s]?number',
                r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'  # Credit card pattern
            ],
            'medical': [
                r'health[_\s]?record', r'medical[_\s]?history', r'diagnosis',
                r'patient[_\s]?id', r'prescription'
            ],
            'business_confidential': [
                r'confidential', r'proprietary', r'trade[_\s]?secret',
                r'internal[_\s]?only', r'classified'
            ]
        }
        
        if custom_keywords_file:
            self._load_custom_keywords(custom_keywords_file)
        
        self.compiled_patterns = self._compile_patterns()

    def _load_custom_keywords(self, filepath: str) -> None:
        """Load custom keywords from a JSON file."""
        try:
            with open(filepath, 'r') as f:
                custom_categories = json.load(f)
                for category, keywords in custom_categories.items():
                    if category in self.keyword_categories:
                        self.keyword_categories[category].extend(keywords)
                    else:
                        self.keyword_categories[category] = keywords
        except Exception as e:
            logging.error(f"Error loading custom keywords: {e}")

    def _compile_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Compile regex patterns for all keywords."""
        compiled = {}
        for category, keywords in self.keyword_categories.items():
            compiled[category] = [
                re.compile(rf"\b{keyword}\b", re.IGNORECASE) 
                for keyword in keywords
            ]
        return compiled

class PSTScanner:
    """Main class for scanning PST files for sensitive information."""

    def __init__(self, 
                 output_dir: str = "pst_output",
                 log_file: str = "pst_scan.log",
                 custom_keywords_file: Optional[str] = None):
        self.output_dir = Path(output_dir)
        self.setup_logging(log_file)
        self.keyword_manager = KeywordManager(custom_keywords_file)
        self.matches: List[SensitiveMatch] = []

    def setup_logging(self, log_file: str) -> None:
        """Configure logging with both file and console handlers."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )

    def verify_pst_file(self, file_path: str) -> bool:
        """Verify if the file is a valid PST file."""
        if not os.path.exists(file_path):
            logging.error(f"File not found: {file_path}")
            return False

        if MAGIC_AVAILABLE:
            file_type = magic.from_file(file_path)
            if "Microsoft Outlook" not in file_type:
                logging.error(f"Invalid file type: {file_type}")
                return False

        return True

    def extract_email_content(self, email_text: str) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """Extract relevant fields from email text."""
        email_id = re.search(r'Message-ID: <(.+?)>', email_text)
        subject = re.search(r'Subject: (.*?)\n', email_text)
        timestamp = re.search(r'Date: (.*?)\n', email_text)
        body = re.search(r'Content-Type: text/plain.*?\n\n(.*?)(?=\n\n|$)', 
                        email_text, re.DOTALL)

        return (
            email_id.group(1) if email_id else None,
            subject.group(1) if subject else None,
            body.group(1) if body else None,
            timestamp.group(1) if timestamp else None
        )

    def scan_email(self, email_text: str) -> Optional[SensitiveMatch]:
        """Scan a single email for sensitive information."""
        email_id, subject, body, timestamp = self.extract_email_content(email_text)
        
        if not any([subject, body]):
            return None

        matched_keywords: Set[str] = set()
        for category, patterns in self.keyword_manager.compiled_patterns.items():
            for pattern in patterns:
                if subject and pattern.search(subject):
                    matched_keywords.add(f"{category}:{pattern.pattern}")
                if body and pattern.search(body):
                    matched_keywords.add(f"{category}:{pattern.pattern}")

        if matched_keywords:
            return SensitiveMatch(
                email_id=email_id or "unknown",
                subject=subject or "no subject",
                matched_keywords=matched_keywords,
                context=body[:200] + "..." if body else "no body",
                timestamp=timestamp or "unknown"
            )
        return None

    def process_pst_chunk(self, emails: List[str]) -> List[SensitiveMatch]:
        """Process a chunk of emails (used for parallel processing)."""
        matches = []
        for email in emails:
            match = self.scan_email(email)
            if match:
                matches.append(match)
        return matches

    def scan_pst(self, file_path: str) -> None:
        """Main method to scan a PST file for sensitive information."""
        if not self.verify_pst_file(file_path):
            return

        try:
            # Create output directory if it doesn't exist
            self.output_dir.mkdir(parents=True, exist_ok=True)
            
            # Extract emails using readpst
            logging.info(f"Extracting emails from: {file_path}")
            output = subprocess.check_output(
                ['readpst', '-r', '-j', str(self.output_dir), file_path],
                universal_newlines=True,
                stderr=subprocess.PIPE
            )

            # Read extracted emails
            emails = []
            for msg_file in self.output_dir.glob("*.msg"):
                with open(msg_file, 'r', encoding='utf-8', errors='ignore') as f:
                    emails.append(f.read())
                msg_file.unlink()  # Clean up extracted files

            # Process emails in parallel
            chunk_size = len(emails) // mp.cpu_count()
            chunks = [emails[i:i + chunk_size] for i in range(0, len(emails), chunk_size)]
            
            with mp.Pool() as pool:
                results = pool.map(self.process_pst_chunk, chunks)

            # Combine results
            for chunk_results in results:
                self.matches.extend(chunk_results)

            # Generate report
            self.generate_report()

        except subprocess.CalledProcessError as e:
            logging.error(f"Error processing PST file: {e.stderr}")
        except Exception as e:
            logging.error(f"Unexpected error: {e}")
        finally:
            # Clean up
            if self.output_dir.exists():
                for file in self.output_dir.glob("*"):
                    file.unlink()
                self.output_dir.rmdir()

    def generate_report(self) -> None:
        """Generate a detailed report of findings."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"pst_scan_report_{timestamp}.json"
        
        report = {
            "scan_timestamp": timestamp,
            "total_matches": len(self.matches),
            "matches": [
                {
                    "email_id": match.email_id,
                    "subject": match.subject,
                    "matched_keywords": list(match.matched_keywords),
                    "context": match.context,
                    "timestamp": match.timestamp
                }
                for match in self.matches
            ]
        }

        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logging.info(f"Scan complete. Report generated: {report_file}")
        logging.info(f"Total matches found: {len(self.matches)}")

def main():
    """Main entry point for the script."""
    if len(sys.argv) != 2:
        print("Usage: python pst_scanner.py <path_to_pst_file>")
        sys.exit(1)

    scanner = PSTScanner(
        output_dir="pst_temp",
        log_file="pst_scan.log",
        custom_keywords_file="custom_keywords.json"
    )
    scanner.scan_pst(sys.argv[1])

if __name__ == "__main__":
    main()
