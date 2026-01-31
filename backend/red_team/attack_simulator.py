import asyncio
import random
from typing import Dict, List, Optional
from datetime import datetime, timezone
from .log_generator import LogGenerator

class AttackSimulator:
    """Simulates various cyber attacks in real-time"""
    
    def __init__(self):
        self.log_generator = LogGenerator()
        self.is_running = False
        self.current_attack_type: Optional[str] = None
        self.logs_generated = 0
        self.attacks_launched = 0
        
    async def start_simulation(self, attack_types: List[str] = None, intensity: str = 'medium'):
        """Start the attack simulation"""
        self.is_running = True
        self.logs_generated = 0
        self.attacks_launched = 0
        
        if attack_types is None:
            attack_types = ['DoS', 'Port Scan', 'Brute Force', 'Malware Beacon']
        
        intensity_settings = {
            'low': {'interval': 2.0, 'batch_size': 5, 'attack_ratio': 0.2},
            'medium': {'interval': 1.0, 'batch_size': 10, 'attack_ratio': 0.3},
            'high': {'interval': 0.5, 'batch_size': 20, 'attack_ratio': 0.5}
        }
        
        settings = intensity_settings.get(intensity, intensity_settings['medium'])
        
        return {
            'status': 'started',
            'attack_types': attack_types,
            'intensity': intensity,
            'settings': settings
        }
    
    def stop_simulation(self):
        """Stop the attack simulation"""
        self.is_running = False
        return {
            'status': 'stopped',
            'total_logs': self.logs_generated,
            'total_attacks': self.attacks_launched
        }
    
    def generate_batch(self, batch_size: int = 10, attack_ratio: float = 0.3) -> List[Dict]:
        """Generate a batch of logs"""
        logs = self.log_generator.generate_mixed_traffic(batch_size, attack_ratio)
        self.logs_generated += len(logs)
        self.attacks_launched += sum(1 for log in logs if log['label'] == 'malicious')
        return logs
    
    def get_status(self) -> Dict:
        """Get current simulation status"""
        return {
            'is_running': self.is_running,
            'logs_generated': self.logs_generated,
            'attacks_launched': self.attacks_launched,
            'current_attack_type': self.current_attack_type
        }
