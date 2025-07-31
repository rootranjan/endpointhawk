#!/usr/bin/env python3
"""
Directory Comparator for EndPointHawk

Compares routes between two local directories without requiring git operations.
Useful for comparing different versions of code, different branches that have been
checked out separately, or comparing against backup/archived versions.
"""

import os
import logging
import threading
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple, Any
from datetime import datetime

from models import (
    RouteInfo, ComparisonResult, RouteChange, FileChange, 
    ComparisonConfig, RiskLevel, ScanResult
)

class DirectoryComparator:
    """
    Compare routes between two local directories.
    
    This comparator scans both directories independently and then analyzes
    the differences in discovered routes.
    """
    
    def __init__(self, scanner):
        """
        Initialize the directory comparator.
        
        Args:
            scanner: AttackSurfaceScanner instance for route detection
        """
        self.scanner = scanner
        self.logger = logging.getLogger(__name__)
        self._file_cache = {}  # Simple in-memory cache for file contents
        self._cache_lock = threading.Lock()  # Thread-safe cache operations
        self._git_lock = threading.Lock()  # Thread-safe Git operations
    
    def compare_directories(self, source_dir: str, target_dir: str, 
                          config: ComparisonConfig) -> ComparisonResult:
        """
        Compare routes between two local directories with parallel processing optimization.
        
        Args:
            source_dir: Path to source directory  
            target_dir: Path to target directory
            config: Comparison configuration
            
        Returns:
            ComparisonResult with detailed analysis
        """
        self.logger.info(f"Comparing directories: {source_dir} -> {target_dir}")
        
        try:
            # Import rich components for progress tracking
            from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
            from rich.console import Console
            console = Console()
            
            # Docker-specific progress configuration
            is_docker = os.environ.get('DOCKER_CONTAINER', 'false').lower() == 'true'
            refresh_rate = 1 if is_docker else 2  # Slower refresh in Docker to prevent buffering
            
            # Validate directories exist
            source_path = Path(source_dir)
            target_path = Path(target_dir)
            
            if not source_path.exists():
                raise ValueError(f"Source directory does not exist: {source_dir}")
            if not target_path.exists():
                raise ValueError(f"Target directory does not exist: {target_dir}")
            
            # Use simpler progress for Docker containers
            if is_docker:
                # Simple single-line progress for Docker - like pip install
                console.print("[cyan]🔍 Comparing directories...[/cyan]", end="")
                
                # Use parallel scanning for better performance
                source_files = self._get_files_to_scan(source_path)
                console.print(".", end="")
                source_routes = self._scan_directory_parallel(source_path, "source", source_files)
                console.print(".", end="")
                
                target_files = self._get_files_to_scan(target_path)
                console.print(".", end="")
                target_routes = self._scan_directory_parallel(target_path, "target", target_files)
                console.print(".", end="")
                
                # Filter out invalid routes (file paths mistaken as API routes)
                source_routes = self._filter_valid_routes(source_routes, str(source_path))
                target_routes = self._filter_valid_routes(target_routes, str(target_path))
                console.print(".", end="")
                
                # Apply filters if specified
                if config.filters:
                    source_routes = self._apply_advanced_filtering(source_routes, config)
                    target_routes = self._apply_advanced_filtering(target_routes, config)
                
                # Compare routes
                route_changes = self._compare_routes(source_routes, target_routes, config)
                console.print(".", end="")
                
                # Analyze file changes (if requested)
                file_changes = []
                if config.include_file_changes:
                    file_changes = self._analyze_file_changes(source_path, target_path)
                    console.print(".", end="")
                
                # Complete the line
                console.print(f" [green]done[/green]")
                console.print(f"[green]✅ Found {len(route_changes)} route changes[/green]")
                
                # Clear cache to free memory
                self._clear_cache()
                
                # Create comparison result
                result = ComparisonResult(
                    source_version=source_dir,
                    target_version=target_dir,
                    comparison_type="directories",
                    changes=route_changes,
                    file_changes=file_changes,
                    scan_metadata={
                        'source_routes_count': len(source_routes),
                        'target_routes_count': len(target_routes),
                        'source_files_count': len(source_files),
                        'target_files_count': len(target_files),
                        'filters_applied': config.filters is not None,
                        'diff_algorithm': config.diff_algorithm
                    }
                )
                
                return result
            
            else:
                # Create progress display for non-Docker environments
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold blue]🔍 Directory Comparison"),
                    BarColumn(complete_style="green", finished_style="bright_green"),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TimeElapsedColumn(),
                    console=console,
                    transient=False,
                    refresh_per_second=refresh_rate,  # Use Docker-optimized refresh rate
                    expand=False  # Prevent layout shifts
                ) as progress:
                
                    # Task 1: Scan source directory (includes file discovery)
                    task1 = progress.add_task("[cyan]Scanning source directory...", total=None)
                    progress.update(task1, description="[cyan]Discovering and analyzing source files...")
                    source_files = self._get_files_to_scan(source_path)
                    source_routes = self._scan_directory_parallel_with_progress(source_path, "source", progress, task1, source_files)
                    
                    # Task 2: Scan target directory (includes file discovery)
                    task2 = progress.add_task("[cyan]Scanning target directory...", total=None)
                    progress.update(task2, description="[cyan]Discovering and analyzing target files...")
                    target_files = self._get_files_to_scan(target_path)
                    target_routes = self._scan_directory_parallel_with_progress(target_path, "target", progress, task2, target_files)
                    
                    # Task 3: Compare routes
                    task3 = progress.add_task("[cyan]Comparing routes...", total=None)
                    progress.update(task3, description="[cyan]Analyzing route differences...")
                    
                    # Filter out invalid routes
                    source_routes = self._filter_valid_routes(source_routes, str(source_path))
                    target_routes = self._filter_valid_routes(target_routes, str(target_path))
                    
                    # Apply filters if specified
                    if config.filters:
                        source_routes = self._apply_advanced_filtering(source_routes, config)
                        target_routes = self._apply_advanced_filtering(target_routes, config)
                    
                    # Compare routes
                    route_changes = self._compare_routes(source_routes, target_routes, config)
                    progress.update(task3, description=f"[cyan]Found {len(route_changes)} changes")
                    
                    # Task 4: Analyze file changes (if requested)
                    file_changes = []
                    if config.include_file_changes:
                        task4 = progress.add_task("[cyan]Analyzing file changes...", total=None)
                        progress.update(task4, description="[cyan]Comparing file modifications...")
                        file_changes = self._analyze_file_changes(source_path, target_path)
                        progress.update(task4, description=f"[cyan]Found {len(file_changes)} file changes")
                    
                    # Complete progress
                    progress.update(task3, description=f"[green]✅ Comparison complete: {len(route_changes)} route changes")
                    
                    # Clear cache to free memory
                    self._clear_cache()
                    
                    # Create comparison result
                    result = ComparisonResult(
                        source_version=source_dir,
                        target_version=target_dir,
                        comparison_type="directories",
                        changes=route_changes,
                        file_changes=file_changes,
                        scan_metadata={
                            'source_routes_count': len(source_routes),
                            'target_routes_count': len(target_routes),
                            'source_files_count': len(source_files),
                            'target_files_count': len(target_files),
                            'filters_applied': config.filters is not None,
                            'diff_algorithm': config.diff_algorithm
                        }
                    )
                    
                    return result
                    
        except Exception as e:
            self.logger.error(f"Error comparing directories: {e}")
            import traceback
            self.logger.error(f"Full traceback: {traceback.format_exc()}")
            raise

    async def _scan_directory_async(self, directory: Path, version_name: str) -> List[RouteInfo]:
        """
        Async version of directory scanning for CLI context.
        """
        self.logger.info(f"Scanning {version_name} directory: {directory}")
        
        try:
            # Create a fresh scanner instance to avoid state contamination
            from endpointhawk_core.endpointhawk import AttackSurfaceScanner
            from models import ScanConfig
            
            # Create a fresh config for this directory scan
            fresh_config = ScanConfig(
                repo_path=str(directory),
                frameworks=self.scanner.config.frameworks,
                use_ai_analysis=self.scanner.config.use_ai_analysis,
                risk_threshold=self.scanner.config.risk_threshold,
                resolve_prefixes=self.scanner.config.resolve_prefixes,
                prefix_config_path=self.scanner.config.prefix_config_path,
                output_formats=self.scanner.config.output_formats,
                output_directory=self.scanner.config.output_directory,
                organization_patterns=self.scanner.config.organization_patterns,
                prefixes_only=self.scanner.config.prefixes_only
            )
            
            # Create fresh scanner instance
            fresh_scanner = AttackSurfaceScanner(fresh_config)
            
            # Run the scan asynchronously
            scan_result = await fresh_scanner.scan_repository()
            
            # Extract routes from scan result
            if hasattr(scan_result, 'routes'):
                return scan_result.routes
            else:
                return []
                
        except Exception as e:
            self.logger.error(f"Error scanning {version_name} directory: {e}")
            return []

    def _scan_directory(self, directory: Path, version_name: str) -> List[RouteInfo]:
        """
        Scan a directory for routes using a simplified approach to avoid threading issues.
        
        Args:
            directory: Directory path to scan
            version_name: Human-readable version name for logging
            
        Returns:
            List of discovered routes
        """
        # Check if running in Docker to avoid multi-line output
        is_docker = os.environ.get('DOCKER_CONTAINER', 'false').lower() == 'true'
        
        if not is_docker:
            self.logger.info(f"Scanning {version_name} directory: {directory}")
        
        try:
            # Use the same detectors as the main scanner but scan files directly
            all_routes = []
            
            # Get all relevant files to scan
            files_to_scan = self._get_files_to_scan(directory)
            
            if not is_docker:
                self.logger.info(f"Found {len(files_to_scan)} files to scan in {version_name}")
            
            # Scan each file using the same detectors
            for file_path in files_to_scan:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # Try each detector
                    for detector in self.scanner.detectors:
                        if detector.can_handle_file(str(file_path), content):
                            file_routes = detector.detect_routes(str(file_path), content)
                            
                            # Add commit information to each route
                            for route in file_routes:
                                # Check if the directory is a git repository and add commit info
                                if hasattr(detector, 'add_commit_info_to_route'):
                                    detector.add_commit_info_to_route(route, str(directory), self.scanner.config)
                            
                            all_routes.extend(file_routes)
                            
                except Exception as e:
                    self.logger.debug(f"Could not read file {file_path}: {e}")
                    continue
            
            if not is_docker:
                self.logger.info(f"Scan completed for {version_name}: {len(all_routes)} routes found")
            return all_routes
                
        except Exception as e:
            self.logger.error(f"Error scanning {version_name} directory: {e}")
            import traceback
            self.logger.error(f"Full traceback: {traceback.format_exc()}")
            return []

    def _scan_directory_parallel(self, directory: Path, version_name: str, files_to_scan: List[Path]) -> List[RouteInfo]:
        """
        Scan a directory for routes using parallel processing for better performance.
        
        Args:
            directory: Directory path to scan
            version_name: Human-readable version name for logging
            files_to_scan: List of files to scan (pre-discovered for efficiency)
            
        Returns:
            List of discovered routes
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import threading
        
        # Check if running in Docker to avoid multi-line output
        is_docker = os.environ.get('DOCKER_CONTAINER', 'false').lower() == 'true'
        
        if not is_docker:
            self.logger.info(f"Scanning {version_name} directory with parallel processing: {directory}")
        
        try:
            all_routes = []
            routes_lock = threading.Lock()  # Thread-safe list operations
            
            # Determine optimal number of workers based on file count
            num_workers = min(8, max(2, len(files_to_scan) // 50))  # 2-8 workers, 50 files per worker
            
            if not is_docker:
                self.logger.info(f"Using {num_workers} workers for {len(files_to_scan)} files in {version_name}")
            
            def scan_single_file(file_path: Path) -> List[RouteInfo]:
                """Scan a single file and return discovered routes"""
                # Use cached file content for better performance
                content = self._get_cached_file_content(file_path)
                if content is None:
                    return []
                
                file_routes = []
                
                # Try each detector
                for detector in self.scanner.detectors:
                    if detector.can_handle_file(str(file_path), content):
                        routes = detector.detect_routes(str(file_path), content)
                        
                        # Add commit information to each route
                        for route in routes:
                            if hasattr(detector, 'add_commit_info_to_route'):
                                detector.add_commit_info_to_route(route, str(directory), self.scanner.config)
                        
                        file_routes.extend(routes)
                
                return file_routes
            
            # Use ThreadPoolExecutor for parallel processing
            with ThreadPoolExecutor(max_workers=num_workers) as executor:
                # Submit all file scanning tasks
                future_to_file = {
                    executor.submit(scan_single_file, file_path): file_path 
                    for file_path in files_to_scan
                }
                
                # Collect results as they complete
                for future in as_completed(future_to_file):
                    try:
                        file_routes = future.result()
                        if file_routes:
                            with routes_lock:
                                all_routes.extend(file_routes)
                    except Exception as e:
                        file_path = future_to_file[future]
                        self.logger.debug(f"Error scanning {file_path}: {e}")
            
            if not is_docker:
                self.logger.info(f"Parallel scan completed for {version_name}: {len(all_routes)} routes found")
            return all_routes
                
        except Exception as e:
            self.logger.error(f"Error in parallel scanning {version_name} directory: {e}")
            import traceback
            self.logger.error(f"Full traceback: {traceback.format_exc()}")
            return []

    def _scan_directory_parallel_with_progress(self, directory: Path, version_name: str, progress, task_id, files_to_scan: List[Path]) -> List[RouteInfo]:
        """
        Scan a directory for routes with parallel processing and progress tracking.
        
        Args:
            directory: Directory path to scan
            version_name: Human-readable version name for logging
            progress: Rich progress object
            task_id: Progress task ID
            files_to_scan: List of files to scan (pre-discovered for efficiency)
            
        Returns:
            List of discovered routes
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import threading
        
        self.logger.info(f"Scanning {version_name} directory with parallel processing: {directory}")
        
        try:
            # Set the total for progress tracking
            progress.update(task_id, total=len(files_to_scan), description=f"[cyan]Analyzing {version_name} files with parallel processing...")
            
            all_routes = []
            routes_lock = threading.Lock()  # Thread-safe list operations
            completed_files = 0
            completed_lock = threading.Lock()  # Thread-safe counter operations
            
            # Determine optimal number of workers based on file count
            num_workers = min(8, max(2, len(files_to_scan) // 50))  # 2-8 workers, 50 files per worker
            
            def scan_single_file(file_path: Path) -> List[RouteInfo]:
                """Scan a single file and return discovered routes"""
                # Use cached file content for better performance
                content = self._get_cached_file_content(file_path)
                if content is None:
                    return []
                
                file_routes = []
                
                # Try each detector
                for detector in self.scanner.detectors:
                    if detector.can_handle_file(str(file_path), content):
                        routes = detector.detect_routes(str(file_path), content)
                        
                        # Add commit information to each route
                        for route in routes:
                            if hasattr(detector, 'add_commit_info_to_route'):
                                detector.add_commit_info_to_route(route, str(directory), self.scanner.config)
                        
                        file_routes.extend(routes)
                
                return file_routes
            
            # Use ThreadPoolExecutor for parallel processing
            with ThreadPoolExecutor(max_workers=num_workers) as executor:
                # Submit all file scanning tasks
                future_to_file = {
                    executor.submit(scan_single_file, file_path): file_path 
                    for file_path in files_to_scan
                }
                
                # Collect results as they complete
                for future in as_completed(future_to_file):
                    try:
                        file_routes = future.result()
                        if file_routes:
                            with routes_lock:
                                all_routes.extend(file_routes)
                    except Exception as e:
                        file_path = future_to_file[future]
                        self.logger.debug(f"Error scanning {file_path}: {e}")
                    
                    # Update progress
                    with completed_lock:
                        completed_files += 1
                        progress.update(task_id, completed=completed_files, description=f"[cyan]Analyzed {completed_files}/{len(files_to_scan)} {version_name} files...")
            
            progress.update(task_id, completed=len(files_to_scan), description=f"[green]✅ {version_name} scan complete: {len(all_routes)} routes found")
            return all_routes
                
        except Exception as e:
            self.logger.error(f"Error in parallel scanning {version_name} directory: {e}")
            import traceback
            self.logger.error(f"Full traceback: {traceback.format_exc()}")
            return []
    
    def _get_files_to_scan(self, directory: Path) -> List[Path]:
        """
        Get list of files to scan in the directory with optimized performance.
        
        Args:
            directory: Directory to scan
            
        Returns:
            List of file paths to scan
        """
        # Use a single optimized glob pattern instead of multiple rglob calls
        # This is much faster than calling rglob for each extension
        patterns = [
            "**/*.js", "**/*.ts", "**/*.jsx", "**/*.tsx",  # JavaScript/TypeScript
            "**/*.py", "**/*.pyx",                         # Python
            "**/*.java", "**/*.kt",                        # Java/Kotlin
            "**/*.go",                                     # Go
            "**/*.php",                                    # PHP
            "**/*.rb",                                     # Ruby
            "**/*.cs",                                     # C#
            "**/*.dart",                                   # Dart/Flutter
            "**/*.proto",                                  # Protocol Buffers
            "**/*.yaml", "**/*.yml",                       # YAML configs
            "**/*.json",                                   # JSON configs
            "**/*.xml",                                    # XML configs
        ]
        
        files = set()  # Use set for O(1) duplicate removal
        
        # Use pathlib's glob with recursive=True for better performance
        for pattern in patterns:
            try:
                files.update(directory.glob(pattern))
            except Exception as e:
                self.logger.debug(f"Error globbing pattern {pattern}: {e}")
                continue
        
        # Add specific framework files
        framework_files = [
            'package.json', 'package-lock.json', 'yarn.lock',
            'requirements.txt', 'Pipfile', 'poetry.lock',
            'pom.xml', 'build.gradle', 'build.gradle.kts',
            'go.mod', 'go.sum',
            'composer.json', 'composer.lock',
            'Gemfile', 'Gemfile.lock',
            'pubspec.yaml', 'pubspec.lock',
        ]
        
        for filename in framework_files:
            try:
                specific_file = directory / filename
                if specific_file.exists():
                    files.add(specific_file)
            except Exception as e:
                self.logger.debug(f"Error checking framework file {filename}: {e}")
                continue
        
        # Filter out non-files and convert to sorted list
        unique_files = sorted([f for f in files if f.is_file()])
        
        return unique_files
    
    def _apply_filters(self, routes: List[RouteInfo], filters) -> List[RouteInfo]:
        """
        Apply comparison filters to route list.
        
        Args:
            routes: List of routes to filter
            filters: ComparisonFilter configuration
            
        Returns:
            Filtered list of routes
        """
        filtered_routes = routes
        
        # Filter by frameworks
        if filters.frameworks:
            filtered_routes = [r for r in filtered_routes 
                             if r.framework in filters.frameworks]
        
        # Filter by HTTP methods
        if filters.methods:
            filtered_routes = [r for r in filtered_routes 
                             if r.method in filters.methods]
        
        # Filter by path patterns (simple string matching for now)
        if filters.paths:
            import fnmatch
            filtered_routes = [r for r in filtered_routes 
                             if any(fnmatch.fnmatch(r.path, pattern) 
                                   for pattern in filters.paths)]
        
        # Filter by file path patterns
        if filters.file_paths:
            import fnmatch
            filtered_routes = [r for r in filtered_routes 
                             if any(fnmatch.fnmatch(r.file_path, pattern) 
                                   for pattern in filters.file_paths)]
        
        # Filter by original path patterns
        if filters.original_paths and hasattr(r, 'original_path'):
            import fnmatch
            filtered_routes = [r for r in filtered_routes 
                             if r.original_path and any(fnmatch.fnmatch(r.original_path, pattern) 
                                                       for pattern in filters.original_paths)]
        
        self.logger.debug(f"Applied filters: {len(routes)} -> {len(filtered_routes)} routes")
        return filtered_routes
    
    def _compare_routes(self, source_routes: List[RouteInfo], 
                       target_routes: List[RouteInfo], 
                       config: ComparisonConfig) -> List[RouteChange]:
        """
        Compare two sets of routes and identify changes using advanced diff algorithms.
        
        Args:
            source_routes: Routes from source directory
            target_routes: Routes from target directory  
            config: Comparison configuration
            
        Returns:
            List of route changes
        """
        self.logger.debug(f"Comparing routes: {len(source_routes)} source vs {len(target_routes)} target")
        
        # Use advanced diff algorithms if specified
        if hasattr(config, 'diff_algorithm') and config.diff_algorithm in ['hybrid', 'semantic', 'structural', 'performance']:
            return self._use_advanced_diff_algorithms(source_routes, target_routes, config)
        
        # Use simple comparison for 'strict', 'fuzzy', and other algorithms
        # Fallback to simple comparison for backward compatibility
        changes = []
        
        # Create lookup dictionaries for efficient comparison
        source_dict = {self._get_route_key(route): route for route in source_routes}
        target_dict = {self._get_route_key(route): route for route in target_routes}
        
        self.logger.debug(f"Source route keys: {list(source_dict.keys())}")
        self.logger.debug(f"Target route keys: {list(target_dict.keys())}")
        
        source_keys = set(source_dict.keys())
        target_keys = set(target_dict.keys())
        
        # Find added routes (in source but not in target) - NEW routes in source
        added_keys = source_keys - target_keys
        self.logger.debug(f"Added route keys: {added_keys}")
        for key in added_keys:
            route = source_dict[key]
            risk_impact = self._assess_change_risk("ADDED", None, route)
            changes.append(RouteChange(
                change_type="ADDED",
                new_route=route,
                risk_impact=risk_impact,
                change_details={'reason': 'Route added in source directory (newer version)'}
            ))
        
        # Find removed routes (in target but not in source) - OLD routes removed from source
        removed_keys = target_keys - source_keys
        self.logger.debug(f"Removed route keys: {removed_keys}")
        for key in removed_keys:
            route = target_dict[key]
            risk_impact = self._assess_change_risk("REMOVED", route, None)
            changes.append(RouteChange(
                change_type="REMOVED",
                old_route=route,
                risk_impact=risk_impact,
                change_details={'reason': 'Route removed from source directory (older version)'}
            ))
        
        # Find potentially modified routes (same key, different details)
        common_keys = source_keys & target_keys
        self.logger.debug(f"Common route keys: {common_keys}")
        for key in common_keys:
            source_route = source_dict[key]
            target_route = target_dict[key]
            
            if self._routes_differ(source_route, target_route):
                risk_impact = self._assess_change_risk("MODIFIED", source_route, target_route)
                differences = self._analyze_route_differences(source_route, target_route)
                changes.append(RouteChange(
                    change_type="MODIFIED",
                    old_route=source_route,
                    new_route=target_route,
                    risk_impact=risk_impact,
                    change_details=differences
                ))
        
        self.logger.debug(f"Route comparison complete: {len(changes)} changes found")
        return changes
    
    def _use_advanced_diff_algorithms(self, source_routes: List[RouteInfo], 
                                     target_routes: List[RouteInfo], 
                                     config: ComparisonConfig) -> List[RouteChange]:
        """
        Use advanced diff algorithms for route comparison.
        
        Args:
            source_routes: Routes from source directory
            target_routes: Routes from target directory  
            config: Comparison configuration
            
        Returns:
            List of route changes using advanced algorithms
        """
        try:
            from .diff_algorithms import AdvancedDiffEngine, DiffAlgorithm
            
            # Map diff algorithm from config
            algorithm_map = {
                'hybrid': DiffAlgorithm.HYBRID,
                'semantic': DiffAlgorithm.SEMANTIC,
                'structural': DiffAlgorithm.STRUCTURAL,
                'performance': DiffAlgorithm.PERFORMANCE,
                'simple': DiffAlgorithm.SIMPLE
            }
            
            algorithm = algorithm_map.get(config.diff_algorithm, DiffAlgorithm.HYBRID)
            
            # Create and use advanced diff engine
            diff_engine = AdvancedDiffEngine(algorithm)
            changes = diff_engine.compare_routes(source_routes, target_routes)
            
            # Log algorithm metrics
            if diff_engine.metrics:
                self.logger.info(f"Advanced diff metrics: {diff_engine.metrics}")
            
            # Convert to RouteChange format expected by the system
            converted_changes = []
            for change in changes:
                # Safe access to risk level
                risk_impact = RiskLevel.LOW
                if hasattr(change, 'risk_impact'):
                    if hasattr(change.risk_impact, 'value'):
                        risk_impact = change.risk_impact
                    else:
                        # Handle string risk levels
                        risk_map = {'LOW': RiskLevel.LOW, 'MEDIUM': RiskLevel.MEDIUM, 'HIGH': RiskLevel.HIGH}
                        risk_impact = risk_map.get(str(change.risk_impact).upper(), RiskLevel.LOW)
                
                route_change = RouteChange(
                    change_type=change.change_type.upper(),
                    old_route=getattr(change, 'old_route', None),
                    new_route=getattr(change, 'new_route', None),
                    risk_impact=risk_impact,
                    change_details={
                        'algorithm': algorithm.value,
                        'confidence': getattr(change, 'confidence', 0.8),
                        'description': getattr(change, 'description', '')
                    }
                )
                converted_changes.append(route_change)
            
            return converted_changes
            
        except ImportError as e:
            self.logger.warning(f"Advanced diff algorithms not available: {e}")
            # Fallback to simple comparison
            return self._simple_route_comparison(source_routes, target_routes, config)
        except Exception as e:
            self.logger.error(f"Error in advanced diff algorithms: {e}")
            # Fallback to simple comparison
            return self._simple_route_comparison(source_routes, target_routes, config)
    
    def _simple_route_comparison(self, source_routes: List[RouteInfo], 
                                target_routes: List[RouteInfo], 
                                config: ComparisonConfig) -> List[RouteChange]:
        """
        Simple route comparison for fallback scenarios.
        
        Args:
            source_routes: Routes from source directory
            target_routes: Routes from target directory  
            config: Comparison configuration
            
        Returns:
            List of route changes using simple comparison
        """
        changes = []
        
        # Create lookup dictionaries for efficient comparison
        source_dict = {self._get_route_key(route): route for route in source_routes}
        target_dict = {self._get_route_key(route): route for route in target_routes}
        
        source_keys = set(source_dict.keys())
        target_keys = set(target_dict.keys())
        
        # Find added routes
        added_keys = target_keys - source_keys
        for key in added_keys:
            route = target_dict[key]
            risk_impact = self._assess_change_risk("ADDED", None, route)
            changes.append(RouteChange(
                change_type="ADDED",
                new_route=route,
                risk_impact=risk_impact,
                change_details={'reason': 'Route added in target directory'}
            ))
        
        # Find removed routes
        removed_keys = source_keys - target_keys
        for key in removed_keys:
            route = source_dict[key]
            risk_impact = self._assess_change_risk("REMOVED", route, None)
            changes.append(RouteChange(
                change_type="REMOVED",
                old_route=route,
                risk_impact=risk_impact,
                change_details={'reason': 'Route removed from source directory'}
            ))
        
        return changes
    
    def _apply_advanced_filtering(self, routes: List[RouteInfo], 
                                 config: ComparisonConfig) -> List[RouteInfo]:
        """
        Apply advanced filtering to routes using the new filtering engine.
        
        Args:
            routes: Routes to filter
            config: Comparison configuration with filters
            
        Returns:
            Filtered routes
        """
        try:
            from .advanced_filtering import AdvancedFilterEngine
            
            # Check if advanced filtering is requested
            if not hasattr(config, 'filters') or not config.filters:
                return routes
            
            filter_engine = AdvancedFilterEngine()
            
            # Parse filter string from config
            filter_string = getattr(config.filters, 'filter_string', '')
            if filter_string:
                criteria = filter_engine.parse_filter_string(filter_string)
                filtered_routes = filter_engine.apply_filters(routes, criteria)
                
                # Log filtering statistics
                stats = filter_engine.get_filter_statistics(routes, criteria)
                self.logger.info(f"Advanced filtering: {stats['filtered_routes']}/{stats['total_routes']} routes ({stats['filter_rate']:.1f}%)")
                
                return filtered_routes
            
            return routes
            
        except ImportError as e:
            self.logger.warning(f"Advanced filtering not available: {e}")
            # Fallback to existing filtering
            return self._apply_filters(routes, config)
        except Exception as e:
            self.logger.error(f"Error in advanced filtering: {e}")
            # Fallback to existing filtering
            return self._apply_filters(routes, config)
    
    def _get_route_key(self, route: RouteInfo) -> str:
        """
        Generate a unique key for route comparison.
        
        Args:
            route: Route to generate key for
            
        Returns:
            Unique string key for the route
        """
        method = route.method.value if hasattr(route.method, 'value') else str(route.method)
        
        # Clean and normalize the route path
        cleaned_path = self._normalize_route_path(route.path, route.file_path)
        
        # For directory comparison, we want to compare routes by method and cleaned path only
        # File path differences are expected between directories
        return f"{method}:{cleaned_path}"
    
    def _normalize_route_path(self, route_path: str, file_path: str) -> str:
        """
        Normalize route path for comparison, handling cases where file paths 
        are incorrectly assigned to route.path.
        
        Args:
            route_path: The route path (may be corrupted with file path)
            file_path: The actual file path
            
        Returns:
            Normalized route path suitable for comparison
        """
        import os
        from pathlib import Path
        
        # If route_path looks like a file path (contains directory separators and file extensions),
        # it's likely corrupted - try to extract a meaningful API path or mark as invalid
        if ('/' in route_path and 
            (route_path.endswith('.js') or route_path.endswith('.ts') or 
             route_path.endswith('.py') or route_path.endswith('.go') or
             'src/' in route_path or 'scripts/' in route_path or 'utils/' in route_path)):
            
            # This is likely a file path assigned to route.path by mistake
            # Extract relative path from the file_path for a more meaningful comparison
            try:
                # Get just the filename without extension as a fallback
                file_name = Path(file_path).stem
                self.logger.warning(f"Route path looks like file path: {route_path}, using filename: {file_name}")
                return f"/invalid-file-route/{file_name}"
            except:
                return "/invalid-route"
        
        # If route_path contains absolute directory paths (like /test-n8n/api-gateway/),
        # try to normalize it to relative path
        if route_path.startswith('/') and ('test-n8n' in route_path or 'api-gateway' in route_path):
            # Extract the API path part after common directory prefixes
            for prefix in ['/test-n8n/api-gateway/', '/test-n8n/api-gateway-1/', 
                          'test-n8n/api-gateway/', 'test-n8n/api-gateway-1/']:
                if prefix in route_path:
                    # This might be a file path, extract relative part
                    relative_part = route_path.split(prefix)[-1]
                    # If it still looks like a file path, mark as invalid
                    if ('/' in relative_part and 
                        (relative_part.endswith('.js') or 'src/' in relative_part or 'scripts/' in relative_part)):
                        file_name = Path(relative_part).stem
                        return f"/invalid-file-route/{file_name}"
                    else:
                        # Might be a valid API path, keep it but normalize
                        return f"/{relative_part}" if not relative_part.startswith('/') else relative_part
        
        # For valid API paths, ensure consistent format
        if not route_path.startswith('/') and route_path:
            route_path = f"/{route_path}"
        
        return route_path or "/unknown"
    
    def _filter_valid_routes(self, routes: List[RouteInfo], base_dir: str) -> List[RouteInfo]:
        """
        Filter out routes that are actually file paths mistaken as API routes.
        
        Args:
            routes: List of routes to filter
            base_dir: Base directory path for context
            
        Returns:
            Filtered list of valid API routes
        """
        valid_routes = []
        invalid_count = 0
        
        for route in routes:
            # Check if route.path looks like a file path
            if self._is_file_path_route(route.path, route.file_path):
                invalid_count += 1
                self.logger.debug(f"Filtering out file-path route: {route.method} {route.path}")
                continue
            
            # Check if it's a real API endpoint
            if self._is_valid_api_route(route.path):
                valid_routes.append(route)
            else:
                invalid_count += 1
                self.logger.debug(f"Filtering out invalid route: {route.method} {route.path}")
        
        if invalid_count > 0:
            self.logger.info(f"Filtered out {invalid_count} invalid file-path routes from {base_dir}")
        
        return valid_routes
    
    def _is_file_path_route(self, route_path: str, file_path: str) -> bool:
        """
        Check if a route path is actually a file path.
        
        Args:
            route_path: The route path to check
            file_path: The source file path
            
        Returns:
            True if route_path appears to be a file path
        """
        # Route path contains file extensions
        if route_path.endswith(('.js', '.ts', '.py', '.go', '.java', '.rb', '.php')):
            return True
        
        # Route path contains typical directory structures
        if any(dir_name in route_path for dir_name in ['src/', 'scripts/', 'utils/', 'lib/', 'dist/', 'build/']):
            return True
        
        # Route path contains the full directory structure from comparison
        if any(dir_name in route_path for dir_name in ['test-n8n/', 'api-gateway']):
            return True
        
        # Route path looks like a filesystem path (more than 3 directory levels)
        if route_path.count('/') > 8:  # Increased from 6 to 8 to allow longer legitimate API routes
            return True
        
        return False
    
    def _is_valid_api_route(self, route_path: str) -> bool:
        """
        Check if a route path looks like a valid API endpoint.
        
        Args:
            route_path: The route path to check
            
        Returns:
            True if route_path appears to be a valid API endpoint
        """
        # Empty or root path
        if not route_path or route_path == "/":
            return True
        
        # Must start with /
        if not route_path.startswith('/'):
            return False
        
        # Should not contain file extensions
        if route_path.endswith(('.js', '.ts', '.py', '.go', '.java', '.rb', '.php', '.html', '.css')):
            return False
        
        # Should not contain typical source code directory names
        if any(dir_name in route_path.lower() for dir_name in ['src', 'scripts', 'utils', 'lib', 'node_modules']):
            return False
        
        # Should look like an API path (contains typical API patterns)
        api_patterns = ['api/', 'auth/', 'users/', 'admin/', 'v1/', 'v2/', 'service/', 'graphql', 'webhook']
        if any(pattern in route_path.lower() for pattern in api_patterns):
            return True
        
        # Generic check: reasonable path length and structure
        path_parts = [part for part in route_path.split('/') if part]
        if len(path_parts) <= 5 and all(len(part) < 50 for part in path_parts):
            return True
        
        return False
    
    def _routes_differ(self, route1: RouteInfo, route2: RouteInfo) -> bool:
        """
        Check if two routes with the same key have different details.
        
        Args:
            route1: First route to compare
            route2: Second route to compare
            
        Returns:
            True if routes have differences
        """
        # Compare key attributes that might change
        return (
            route1.authenticated != route2.authenticated or
            route1.auth_type != route2.auth_type or
            route1.risk_score != route2.risk_score or
            len(route1.parameters) != len(route2.parameters) or
            route1.line_number != route2.line_number
        )
    
    def _analyze_route_differences(self, old_route: RouteInfo, new_route: RouteInfo) -> Dict[str, Any]:
        """
        Analyze specific differences between two routes.
        
        Args:
            old_route: Original route
            new_route: Modified route
            
        Returns:
            Dictionary of detected differences
        """
        differences = {}
        
        if old_route.authenticated != new_route.authenticated:
            differences['authentication_changed'] = {
                'old': old_route.authenticated,
                'new': new_route.authenticated
            }
        
        if old_route.auth_type != new_route.auth_type:
            differences['auth_type_changed'] = {
                'old': str(old_route.auth_type),
                'new': str(new_route.auth_type)
            }
        
        if old_route.risk_score != new_route.risk_score:
            differences['risk_score_changed'] = {
                'old': old_route.risk_score,
                'new': new_route.risk_score,
                'delta': new_route.risk_score - old_route.risk_score
            }
        
        if len(old_route.parameters) != len(new_route.parameters):
            differences['parameters_count_changed'] = {
                'old': len(old_route.parameters),
                'new': len(new_route.parameters)
            }
        
        if old_route.line_number != new_route.line_number:
            differences['line_number_changed'] = {
                'old': old_route.line_number,
                'new': new_route.line_number
            }
        
        return differences
    
    def _assess_change_risk(self, change_type: str, old_route: Optional[RouteInfo], 
                           new_route: Optional[RouteInfo]) -> RiskLevel:
        """
        Assess the security risk impact of a route change.
        
        Args:
            change_type: Type of change (ADDED, REMOVED, MODIFIED)
            old_route: Original route (if any)
            new_route: New route (if any)
            
        Returns:
            Risk level for this change
        """
        if change_type == "ADDED":
            if new_route and not new_route.authenticated:
                return RiskLevel.HIGH  # New unauthenticated endpoint
            return RiskLevel.MEDIUM
        
        elif change_type == "REMOVED":
            return RiskLevel.LOW  # Removing endpoints is generally lower risk
        
        elif change_type == "MODIFIED":
            if old_route and new_route:
                # Check if authentication was removed
                if old_route.authenticated and not new_route.authenticated:
                    return RiskLevel.HIGH
                # Check if risk score increased significantly
                if new_route.risk_score > old_route.risk_score + 2.0:
                    return RiskLevel.HIGH
                return RiskLevel.MEDIUM
        
        return RiskLevel.LOW
    
    def _analyze_file_changes(self, source_dir: Path, target_dir: Path) -> List[FileChange]:
        """
        Analyze file-level changes between directories.
        
        Args:
            source_dir: Source directory path
            target_dir: Target directory path
            
        Returns:
            List of file changes
        """
        self.logger.debug("Analyzing file-level changes")
        file_changes = []
        
        try:
            # Get all relevant files from both directories
            source_files = self._get_relevant_files(source_dir)
            target_files = self._get_relevant_files(target_dir)
            
            # Convert to relative paths for comparison
            source_rel_files = {f.relative_to(source_dir): f for f in source_files}
            target_rel_files = {f.relative_to(target_dir): f for f in target_files}
            
            source_rel_paths = set(source_rel_files.keys())
            target_rel_paths = set(target_rel_files.keys())
            
            # Find added files
            added_files = target_rel_paths - source_rel_paths
            for rel_path in added_files:
                file_changes.append(FileChange(
                    file_path=str(rel_path),
                    change_type="ADDED",
                    size_change=target_rel_files[rel_path].stat().st_size
                ))
            
            # Find removed files
            removed_files = source_rel_paths - target_rel_paths
            for rel_path in removed_files:
                file_changes.append(FileChange(
                    file_path=str(rel_path),
                    change_type="REMOVED",
                    size_change=-source_rel_files[rel_path].stat().st_size
                ))
            
            # Find modified files (simple size-based check for now)
            common_files = source_rel_paths & target_rel_paths
            for rel_path in common_files:
                source_size = source_rel_files[rel_path].stat().st_size
                target_size = target_rel_files[rel_path].stat().st_size
                
                if source_size != target_size:
                    file_changes.append(FileChange(
                        file_path=str(rel_path),
                        change_type="MODIFIED",
                        size_change=target_size - source_size
                    ))
            
            self.logger.debug(f"File analysis complete: {len(file_changes)} file changes found")
            
        except Exception as e:
            self.logger.error(f"Error analyzing file changes: {e}")
        
        return file_changes
    
    def _get_relevant_files(self, directory: Path) -> List[Path]:
        """
        Get list of relevant files for route detection.
        
        Args:
            directory: Directory to scan
            
        Returns:
            List of relevant file paths
        """
        relevant_extensions = {'.js', '.ts', '.py', '.go', '.java', '.jsx', '.tsx'}
        exclude_patterns = {'node_modules', '.git', 'dist', 'build', '__pycache__', '.venv', 'venv'}
        
        files = []
        for file_path in directory.rglob('*'):
            if (file_path.is_file() and 
                file_path.suffix.lower() in relevant_extensions and
                not any(pattern in str(file_path) for pattern in exclude_patterns)):
                files.append(file_path)
        
        return files 

    def _get_cached_file_content(self, file_path: Path) -> Optional[str]:
        """
        Get file content from cache or read from disk.
        
        Args:
            file_path: Path to the file
            
        Returns:
            File content or None if file cannot be read
        """
        file_str = str(file_path)
        
        # Check cache first
        with self._cache_lock:
            if file_str in self._file_cache:
                return self._file_cache[file_str]
        
        # Read from disk
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Cache the content
            with self._cache_lock:
                self._file_cache[file_str] = content
            
            return content
        except Exception as e:
            self.logger.debug(f"Could not read file {file_path}: {e}")
            return None

    def _clear_cache(self):
        """Clear the file content cache to free memory"""
        with self._cache_lock:
            self._file_cache.clear() 