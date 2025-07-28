#!/usr/bin/env python3
"""
Git utilities for EndPointHawk

Provides functionality to extract git commit information for routes,
including author details, commit hashes, and timestamps.
"""

import os
import subprocess
import logging
from typing import Dict, Optional, Tuple
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

class GitInfoExtractor:
    """Extract git commit information for files and specific lines"""
    
    # Class-level cache to avoid repeated warnings for the same repository
    _git_repo_cache = {}
    _warning_logged = set()
    
    def __init__(self, repo_path: str):
        """
        Initialize the git info extractor.
        
        Args:
            repo_path: Path to the git repository
        """
        self.repo_path = Path(repo_path).resolve()
        self._is_git_repo = self._validate_git_repo()
    
    def _validate_git_repo(self) -> bool:
        """Validate that the path is a git repository"""
        repo_str = str(self.repo_path)
        
        # Check cache first
        if repo_str in self._git_repo_cache:
            return self._git_repo_cache[repo_str]
        
        git_dir = self.repo_path / '.git'
        is_git_repo = git_dir.exists()
        
        # Cache the result
        self._git_repo_cache[repo_str] = is_git_repo
        
        # Only log warning once per repository
        if not is_git_repo and repo_str not in self._warning_logged:
            logger.debug(f"Repository is not a git repository: {self.repo_path}")
            self._warning_logged.add(repo_str)
        
        return is_git_repo
    
    def get_commit_info_for_line(self, file_path: str, line_number: int) -> Dict[str, Optional[str]]:
        """
        Get commit information for a specific line in a file.
        
        Args:
            file_path: Path to the file (relative to repo root)
            line_number: Line number in the file
            
        Returns:
            Dictionary with commit information
        """
        try:
            # Convert to relative path from repo root
            abs_file_path = Path(file_path).resolve()
            rel_file_path = abs_file_path.relative_to(self.repo_path)
            
            # Get the commit that last modified this line
            cmd = [
                'git', 'blame', '-L', f'{line_number},{line_number}',
                '--porcelain', str(rel_file_path)
            ]
            
            result = subprocess.run(
                cmd,
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                logger.warning(f"Git blame failed for {file_path}:{line_number}: {result.stderr}")
                return self._empty_commit_info()
            
            return self._parse_blame_output(result.stdout, line_number)
            
        except Exception as e:
            logger.warning(f"Error getting commit info for {file_path}:{line_number}: {e}")
            return self._empty_commit_info()
    
    def get_commit_info_for_file(self, file_path: str) -> Dict[str, Optional[str]]:
        """
        Get commit information for the most recent commit that modified a file.
        
        Args:
            file_path: Path to the file (relative to repo root)
            
        Returns:
            Dictionary with commit information
        """
        try:
            # Convert to relative path from repo root
            abs_file_path = Path(file_path).resolve()
            rel_file_path = abs_file_path.relative_to(self.repo_path)
            
            # Get the most recent commit for this file
            cmd = [
                'git', 'log', '-1', '--format=%H%n%an%n%ae%n%at%n%s',
                '--', str(rel_file_path)
            ]
            
            result = subprocess.run(
                cmd,
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                logger.warning(f"Git log failed for {file_path}: {result.stderr}")
                return self._empty_commit_info()
            
            return self._parse_log_output(result.stdout)
            
        except Exception as e:
            logger.warning(f"Error getting commit info for {file_path}: {e}")
            return self._empty_commit_info()
    
    def _parse_blame_output(self, output: str, line_number: int) -> Dict[str, Optional[str]]:
        """Parse git blame porcelain output"""
        lines = output.strip().split('\n')
        
        commit_info = self._empty_commit_info()
        
        for line in lines:
            if line.startswith('author '):
                commit_info['commit_author'] = line[7:]
            elif line.startswith('author-mail '):
                # Remove < > from email
                email = line[12:].strip()
                if email.startswith('<') and email.endswith('>'):
                    email = email[1:-1]
                commit_info['commit_author_email'] = email
            elif line.startswith('author-time '):
                timestamp = int(line[12:])
                commit_info['commit_date'] = datetime.fromtimestamp(timestamp).isoformat()
            elif line.startswith('summary '):
                commit_info['commit_message'] = line[8:]
            elif line.startswith('\t'):
                # This is the actual line content, we can extract the commit hash
                # The commit hash is in the first line of blame output
                if len(lines) > 0 and ' ' in lines[0]:
                    commit_info['commit_hash'] = lines[0].split()[0]
                break
        
        return commit_info
    
    def _parse_log_output(self, output: str) -> Dict[str, Optional[str]]:
        """Parse git log output"""
        lines = output.strip().split('\n')
        
        if len(lines) < 5:
            return self._empty_commit_info()
        
        commit_info = {
            'commit_hash': lines[0] if lines[0] else None,
            'commit_author': lines[1] if len(lines) > 1 and lines[1] else None,
            'commit_author_email': lines[2] if len(lines) > 2 and lines[2] else None,
            'commit_date': datetime.fromtimestamp(int(lines[3])).isoformat() if len(lines) > 3 and lines[3] else None,
            'commit_message': lines[4] if len(lines) > 4 and lines[4] else None
        }
        
        return commit_info
    
    def _empty_commit_info(self) -> Dict[str, Optional[str]]:
        """Return empty commit information"""
        return {
            'commit_hash': None,
            'commit_author': None,
            'commit_author_email': None,
            'commit_date': None,
            'commit_message': None
        }
    
    def is_git_repo(self) -> bool:
        """Check if the current directory is a git repository"""
        return self._is_git_repo

def extract_commit_info_for_route(repo_path: str, file_path: str, line_number: int) -> Dict[str, Optional[str]]:
    """
    Extract commit information for a specific route.
    
    Args:
        repo_path: Path to the git repository
        file_path: Path to the file containing the route
        line_number: Line number where the route is defined
        
    Returns:
        Dictionary with commit information
    """
    try:
        extractor = GitInfoExtractor(repo_path)
        if not extractor.is_git_repo():
            return {
                'commit_hash': None,
                'commit_author': None,
                'commit_author_email': None,
                'commit_date': None,
                'commit_message': None
            }
        
        return extractor.get_commit_info_for_line(file_path, line_number)
        
    except Exception as e:
        logger.warning(f"Error extracting commit info: {e}")
        return {
            'commit_hash': None,
            'commit_author': None,
            'commit_author_email': None,
            'commit_date': None,
            'commit_message': None
        } 