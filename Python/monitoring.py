import psutil
import json
import time
from datetime import datetime
from typing import Dict, List, Any
import docker
from pathlib import Path

class ServerMonitor:
    def __init__(self, metrics_dir: str = "./metrics", batch_size: int = 100):
        self.metrics_dir = Path(metrics_dir)
        self.metrics_dir.mkdir(exist_ok=True)
        self.batch_size = batch_size
        self.current_batch = []
        self.docker_client = docker.from_env()

    def collect_system_metrics(self) -> Dict[str, Any]:
        """Collect system-wide metrics."""
        cpu_times = psutil.cpu_times_percent()
        virtual_mem = psutil.virtual_memory()
        disk_usage = psutil.disk_usage('/')
        
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "system": {
                "cpu": {
                    "user": cpu_times.user,
                    "system": cpu_times.system,
                    "idle": cpu_times.idle,
                    "percent": psutil.cpu_percent(interval=1),
                },
                "memory": {
                    "total": virtual_mem.total,
                    "available": virtual_mem.available,
                    "used": virtual_mem.used,
                    "percent": virtual_mem.percent,
                },
                "disk": {
                    "total": disk_usage.total,
                    "used": disk_usage.used,
                    "free": disk_usage.free,
                    "percent": disk_usage.percent,
                },
                "network": self._get_network_stats()
            }
        }

    def collect_container_metrics(self) -> List[Dict[str, Any]]:
        """Collect metrics for all running Odamex containers."""
        container_metrics = []
        
        for container in self.docker_client.containers.list():
            if container.name.startswith('odamex_'):
                stats = container.stats(stream=False)  # Get a single stats reading
                
                metrics = {
                    "container_name": container.name,
                    "cpu_percent": self._calculate_cpu_percent(stats),
                    "memory": {
                        "usage": stats["memory_stats"].get("usage", 0),
                        "limit": stats["memory_stats"].get("limit", 0),
                        "percent": self._calculate_memory_percent(stats)
                    },
                    "network": {
                        "rx_bytes": stats["networks"]["eth0"]["rx_bytes"],
                        "tx_bytes": stats["networks"]["eth0"]["tx_bytes"]
                    },
                    "status": container.status
                }
                container_metrics.append(metrics)
        
        return container_metrics

    def _get_network_stats(self) -> Dict[str, int]:
        """Collect network statistics."""
        net_io = psutil.net_io_counters()
        return {
            "bytes_sent": net_io.bytes_sent,
            "bytes_recv": net_io.bytes_recv,
            "packets_sent": net_io.packets_sent,
            "packets_recv": net_io.packets_recv,
            "errors_in": net_io.errin,
            "errors_out": net_io.errout
        }

    def _calculate_cpu_percent(self, stats: Dict) -> float:
        """Calculate CPU percentage from container stats."""
        cpu_delta = stats["cpu_stats"]["cpu_usage"]["total_usage"] - \
                   stats["precpu_stats"]["cpu_usage"]["total_usage"]
        system_delta = stats["cpu_stats"]["system_cpu_usage"] - \
                      stats["precpu_stats"]["system_cpu_usage"]
        
        if system_delta > 0 and cpu_delta > 0:
            return (cpu_delta / system_delta) * 100.0
        return 0.0

    def _calculate_memory_percent(self, stats: Dict) -> float:
        """Calculate memory percentage from container stats."""
        usage = stats["memory_stats"].get("usage", 0)
        limit = stats["memory_stats"].get("limit", 1)
        if limit > 0:
            return (usage / limit) * 100.0
        return 0.0

    def collect_all_metrics(self) -> Dict[str, Any]:
        """Collect all metrics and return as a single document."""
        return {
            "system_metrics": self.collect_system_metrics(),
            "container_metrics": self.collect_container_metrics()
        }

    def store_metrics_batch(self) -> None:
        """Store the current batch of metrics if it reaches batch_size."""
        if len(self.current_batch) >= self.batch_size:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = self.metrics_dir / f"metrics_batch_{timestamp}.json"
            
            with open(filename, 'w') as f:
                json.dump(self.current_batch, f, indent=2)
            
            self.current_batch = []
            
    def update_metrics(self) -> None:
        """Collect and store metrics."""
        metrics = self.collect_all_metrics()
        self.current_batch.append(metrics)
        self.store_metrics_batch()