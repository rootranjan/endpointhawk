#!/usr/bin/env python3
"""
Git utilities for EndPointHawk

Provides functionality to extract git commit information for routes,
including author details, commit hashes, and timestamps.

IMPORTANT: This module now handles the distinction between original authors and last committers.
For merge commits, it can attempt to find the original author of the changes instead of
just showing the person who last merged the changes. This is controlled by the
prefer_original_author parameter.

Example:
    - Original commit: Khoa Nguyen adds new API endpoint
    - Merge commit: Weihang Huang merges the PR
    - With prefer_original_author=True: Shows Khoa Nguyen as the author
    - With prefer_original_author=False: Shows Weihang Huang as the author
"""

import os
import subprocess
import logging
from typing import Dict, Optional, Tuple, List
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

import threading

class GitInfoExtractor:
    """Extract git commit information for files and specific lines"""
    
    # Class-level cache to avoid repeated warnings for the same repository
    _git_repo_cache = {}
    _warning_logged = set()
    _git_config_lock = threading.Lock()  # Thread-safe Git config operations
    _safe_directories_added = set()  # Track which directories have been added to safe.directory
    
    def __init__(self, repo_path: str):
        """
        Initialize the git info extractor.
        
        Args:
            repo_path: Path to the git repository
        """
        self.repo_path = Path(repo_path).resolve()
        self._is_git_repo = self._validate_git_repo()
        
        # Configure Git for CI environments if needed
        if self._is_git_repo:
            self._configure_git_for_ci()
    
    def _configure_git_for_ci(self):
        """Configure Git to handle CI environment ownership issues"""
        try:
            # Check if we're in a CI environment
            ci_env = any([
                os.environ.get('CI', '').lower() == 'true',
                os.environ.get('GITLAB_CI', '').lower() == 'true',
                os.environ.get('GITHUB_ACTIONS', '').lower() == 'true',
                os.environ.get('JENKINS_URL'),
                os.environ.get('BUILD_ID')
            ])
            
            if ci_env:
                # Add repository to safe.directory to handle ownership issues (thread-safe)
                repo_str = str(self.repo_path)
                with self._git_config_lock:
                    # Check if we've already added this directory
                    if repo_str in self._safe_directories_added:
                        logger.debug(f"Directory {repo_str} already added to Git safe.directory")
                        return
                    
                    result = subprocess.run(
                        ['git', 'config', '--global', '--add', 'safe.directory', repo_str],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    
                    if result.returncode == 0:
                        logger.debug(f"Added {repo_str} to Git safe.directory for CI environment")
                        self._safe_directories_added.add(repo_str)
                    else:
                        logger.warning(f"Failed to add {repo_str} to Git safe.directory: {result.stderr}")
                    
        except Exception as e:
            logger.warning(f"Error configuring Git for CI environment: {e}")
    
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
    
    def get_commit_info_for_line(self, file_path: str, line_number: int, prefer_original_author: bool = True) -> Dict[str, Optional[str]]:
        """
        Get commit information for a specific line in a file.
        
        Args:
            file_path: Path to the file (relative to repo root)
            line_number: Line number in the file
            prefer_original_author: If True, try to get the original author instead of last committer
            
        Returns:
            Dictionary with commit information
        """
        try:
            # Convert to relative path from repo root
            abs_file_path = Path(file_path).resolve()
            rel_file_path = abs_file_path.relative_to(self.repo_path)
            
            # First check if the file exists in HEAD
            check_cmd = ['git', 'ls-files', str(rel_file_path)]
            check_result = subprocess.run(
                check_cmd,
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # If file doesn't exist in HEAD, it's likely a new file
            if check_result.returncode != 0 or not check_result.stdout.strip():
                logger.debug(f"File {rel_file_path} does not exist in HEAD - likely a new file")
                return self._empty_commit_info()
            
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
                # Check if it's a "no such path" error (file doesn't exist in HEAD)
                if "fatal: no such path" in result.stderr:
                    logger.debug(f"File {rel_file_path} does not exist in HEAD - likely a new file")
                    return self._empty_commit_info()
                else:
                    logger.warning(f"Git blame failed for {file_path}:{line_number}: {result.stderr}")
                    return self._empty_commit_info()
            
            commit_info = self._parse_blame_output(result.stdout, line_number)
            
            # If we prefer original author and this looks like a merge commit, try to get the original author
            if prefer_original_author and commit_info.get('commit_message', '').startswith('Merge'):
                original_author_info = self._get_original_author_for_merge_commit(
                    commit_info.get('commit_hash'), file_path, line_number
                )
                if original_author_info:
                    # Use original author info but keep the merge commit hash and message
                    commit_info.update(original_author_info)
            
            return commit_info
            
        except Exception as e:
            logger.warning(f"Error getting commit info for {file_path}:{line_number}: {e}")
            return self._empty_commit_info()
    
    def get_line_authorship_history(self, file_path: str, line_number: int, max_history: int = 5) -> List[Dict[str, Optional[str]]]:
        """
        Get the complete authorship history for a specific line.
        
        Args:
            file_path: Path to the file (relative to repo root)
            line_number: Line number in the file
            max_history: Maximum number of historical entries to return
            
        Returns:
            List of dictionaries with commit information, ordered from newest to oldest
        """
        try:
            # Convert to relative path from repo root
            abs_file_path = Path(file_path).resolve()
            rel_file_path = abs_file_path.relative_to(self.repo_path)
            
            # Get the complete blame history for this line
            cmd = [
                'git', 'blame', '-L', f'{line_number},{line_number}',
                '--porcelain', '--reverse', str(rel_file_path)
            ]
            
            result = subprocess.run(
                cmd,
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                logger.warning(f"Git blame history failed for {file_path}:{line_number}: {result.stderr}")
                return []
            
            # Parse the blame history
            history = self._parse_blame_history_output(result.stdout, max_history)
            return history
            
        except Exception as e:
            logger.warning(f"Error getting authorship history for {file_path}:{line_number}: {e}")
            return []
    
    def _get_original_author_for_merge_commit(self, commit_hash: str, file_path: str, line_number: int) -> Optional[Dict[str, str]]:
        """
        For merge commits, try to find the original author of the changes.
        
        Args:
            commit_hash: The merge commit hash
            file_path: Path to the file
            line_number: Line number in the file
            
        Returns:
            Dictionary with original author information or None if not found
        """
        try:
            if not commit_hash:
                return None
                
            # Convert to relative path from repo root
            abs_file_path = Path(file_path).resolve()
            rel_file_path = abs_file_path.relative_to(self.repo_path)
            
            # Get the parent commits of the merge commit
            cmd = ['git', 'log', '--format=%H', '--max-count=2', commit_hash + '^']
            result = subprocess.run(
                cmd,
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                return None
                
            parent_commits = result.stdout.strip().split('\n')
            if len(parent_commits) < 2:
                return None
            
            # Check which parent introduced the change
            for parent in parent_commits:
                if not parent.strip():
                    continue
                    
                # Check if this line exists in the parent commit
                cmd = [
                    'git', 'blame', '-L', f'{line_number},{line_number}',
                    '--porcelain', parent, '--', str(rel_file_path)
                ]
                
                result = subprocess.run(
                    cmd,
                    cwd=self.repo_path,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    # Parse the blame output to get the original author
                    lines = result.stdout.strip().split('\n')
                    original_author = None
                    original_author_email = None
                    
                    for line in lines:
                        if line.startswith('author '):
                            original_author = line[7:]
                        elif line.startswith('author-mail '):
                            email = line[12:].strip()
                            if email.startswith('<') and email.endswith('>'):
                                email = email[1:-1]
                            original_author_email = email
                        elif line.startswith('\t'):
                            break
                    
                    if original_author and original_author_email:
                        return {
                            'commit_author': original_author,
                            'commit_author_email': original_author_email
                        }
            
            return None
            
        except Exception as e:
            logger.debug(f"Error getting original author for merge commit {commit_hash}: {e}")
            return None
    
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
            
            # First check if the file exists in HEAD
            check_cmd = ['git', 'ls-files', str(rel_file_path)]
            check_result = subprocess.run(
                check_cmd,
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # If file doesn't exist in HEAD, it's likely a new file
            if check_result.returncode != 0 or not check_result.stdout.strip():
                logger.debug(f"File {rel_file_path} does not exist in HEAD - likely a new file")
                return self._empty_commit_info()
            
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
                # Check if it's a "no such path" error (file doesn't exist in HEAD)
                if "fatal: no such path" in result.stderr:
                    logger.debug(f"File {rel_file_path} does not exist in HEAD - likely a new file")
                    return self._empty_commit_info()
                else:
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

def extract_commit_info_for_route(repo_path: str, file_path: str, line_number: int, prefer_original_author: bool = True) -> Dict[str, Optional[str]]:
    """
    Extract commit information for a specific route.
    
    Args:
        repo_path: Path to the git repository
        file_path: Path to the file containing the route
        line_number: Line number where the route is defined
        prefer_original_author: If True, try to get the original author instead of last committer
        
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
        
        return extractor.get_commit_info_for_line(file_path, line_number, prefer_original_author)
        
    except Exception as e:
        logger.warning(f"Error extracting commit info: {e}")
        return {
            'commit_hash': None,
            'commit_author': None,
            'commit_author_email': None,
            'commit_date': None,
            'commit_message': None
        }

def extract_authorship_history_for_route(repo_path: str, file_path: str, line_number: int, max_history: int = 5) -> List[Dict[str, Optional[str]]]:
    """
    Extract complete authorship history for a specific route.
    
    Args:
        repo_path: Path to the git repository
        file_path: Path to the file containing the route
        line_number: Line number where the route is defined
        max_history: Maximum number of historical entries to return
        
    Returns:
        List of dictionaries with commit information, ordered from newest to oldest
    """
    try:
        extractor = GitInfoExtractor(repo_path)
        if not extractor.is_git_repo():
            return []
        
        return extractor.get_line_authorship_history(file_path, line_number, max_history)
        
    except Exception as e:
        logger.warning(f"Error extracting authorship history: {e}")
        return [] 