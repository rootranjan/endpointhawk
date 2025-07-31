#!/usr/bin/env python3
"""
Performance Monitor for EndPointHawk

Tracks and reports performance metrics for directory comparison operations.
"""

import time
import psutil
import threading
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
import logging

@dataclass
class PerformanceMetrics:
    """Performance metrics for a single operation"""
    operation_name: str
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    files_processed: int = 0
    routes_found: int = 0
    memory_peak_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    cache_hits: int = 0
    cache_misses: int = 0
    workers_used: int = 0
    
    @property
    def duration_seconds(self) -> float:
        """Calculate operation duration in seconds"""
        if self.end_time is None:
            return time.time() - self.start_time
        return self.end_time - self.start_time
    
    @property
    def files_per_second(self) -> float:
        """Calculate files processed per second"""
        duration = self.duration_seconds
        return self.files_processed / duration if duration > 0 else 0.0
    
    @property
    def cache_hit_rate(self) -> float:
        """Calculate cache hit rate percentage"""
        total = self.cache_hits + self.cache_misses
        return (self.cache_hits / total * 100) if total > 0 else 0.0

class PerformanceMonitor:
    """Monitors and tracks performance metrics"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.metrics: Dict[str, PerformanceMetrics] = {}
        self._monitoring = False
        self._monitor_thread = None
        self._stop_monitoring = threading.Event()
        
    def start_operation(self, operation_name: str) -> str:
        """Start monitoring a new operation"""
        operation_id = f"{operation_name}_{int(time.time())}"
        self.metrics[operation_id] = PerformanceMetrics(operation_name=operation_name)
        
        if not self._monitoring:
            self._start_background_monitoring()
        
        self.logger.info(f"Started performance monitoring for: {operation_name}")
        return operation_id
    
    def end_operation(self, operation_id: str):
        """End monitoring an operation"""
        if operation_id in self.metrics:
            self.metrics[operation_id].end_time = time.time()
            self.logger.info(f"Ended performance monitoring for: {self.metrics[operation_id].operation_name}")
    
    def update_metrics(self, operation_id: str, **kwargs):
        """Update metrics for an operation"""
        if operation_id in self.metrics:
            metrics = self.metrics[operation_id]
            for key, value in kwargs.items():
                if hasattr(metrics, key):
                    setattr(metrics, key, value)
    
    def get_performance_report(self, operation_id: str) -> Dict[str, Any]:
        """Get a detailed performance report for an operation"""
        if operation_id not in self.metrics:
            return {}
        
        metrics = self.metrics[operation_id]
        
        return {
            "operation_name": metrics.operation_name,
            "duration_seconds": metrics.duration_seconds,
            "files_processed": metrics.files_processed,
            "routes_found": metrics.routes_found,
            "files_per_second": metrics.files_per_second,
            "memory_peak_mb": metrics.memory_peak_mb,
            "cpu_usage_percent": metrics.cpu_usage_percent,
            "cache_hit_rate": metrics.cache_hit_rate,
            "workers_used": metrics.workers_used,
            "start_time": datetime.fromtimestamp(metrics.start_time).isoformat(),
            "end_time": datetime.fromtimestamp(metrics.end_time).isoformat() if metrics.end_time else None
        }
    
    def get_comparison_report(self, operation_id_1: str, operation_id_2: str) -> Dict[str, Any]:
        """Compare performance between two operations"""
        report1 = self.get_performance_report(operation_id_1)
        report2 = self.get_performance_report(operation_id_2)
        
        if not report1 or not report2:
            return {}
        
        comparison = {
            "operation_1": report1,
            "operation_2": report2,
            "improvements": {}
        }
        
        # Calculate improvements
        if report1["duration_seconds"] > 0 and report2["duration_seconds"] > 0:
            speed_improvement = ((report1["duration_seconds"] - report2["duration_seconds"]) / report1["duration_seconds"]) * 100
            comparison["improvements"]["speed_improvement_percent"] = speed_improvement
            
            throughput_improvement = ((report2["files_per_second"] - report1["files_per_second"]) / report1["files_per_second"]) * 100
            comparison["improvements"]["throughput_improvement_percent"] = throughput_improvement
        
        return comparison
    
    def _start_background_monitoring(self):
        """Start background monitoring of system resources"""
        self._monitoring = True
        self._stop_monitoring.clear()
        self._monitor_thread = threading.Thread(target=self._monitor_resources, daemon=True)
        self._monitor_thread.start()
    
    def _monitor_resources(self):
        """Monitor system resources in background"""
        while not self._stop_monitoring.is_set():
            try:
                # Get current memory and CPU usage
                memory_mb = psutil.virtual_memory().used / (1024 * 1024)
                cpu_percent = psutil.cpu_percent(interval=1)
                
                # Update all active operations
                for operation_id, metrics in self.metrics.items():
                    if metrics.end_time is None:  # Only update active operations
                        metrics.memory_peak_mb = max(metrics.memory_peak_mb, memory_mb)
                        metrics.cpu_usage_percent = max(metrics.cpu_usage_percent, cpu_percent)
                
                time.sleep(2)  # Update every 2 seconds
                
            except Exception as e:
                self.logger.debug(f"Error in resource monitoring: {e}")
                time.sleep(5)  # Wait longer on error
    
    def stop_monitoring(self):
        """Stop background monitoring"""
        self._monitoring = False
        self._stop_monitoring.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
    
    def print_performance_summary(self, operation_id: str):
        """Print a formatted performance summary"""
        report = self.get_performance_report(operation_id)
        if not report:
            return
        
        print(f"\n{'='*60}")
        print(f"PERFORMANCE SUMMARY: {report['operation_name']}")
        print(f"{'='*60}")
        print(f"Duration: {report['duration_seconds']:.2f} seconds")
        print(f"Files Processed: {report['files_processed']:,}")
        print(f"Routes Found: {report['routes_found']:,}")
        print(f"Throughput: {report['files_per_second']:.1f} files/second")
        print(f"Memory Peak: {report['memory_peak_mb']:.1f} MB")
        print(f"CPU Usage: {report['cpu_usage_percent']:.1f}%")
        print(f"Cache Hit Rate: {report['cache_hit_rate']:.1f}%")
        print(f"Workers Used: {report['workers_used']}")
        print(f"{'='*60}\n")

# Global performance monitor instance
performance_monitor = PerformanceMonitor() 