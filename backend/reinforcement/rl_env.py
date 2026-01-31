import gymnasium as gym
from gymnasium import spaces
import numpy as np
from typing import Dict, Tuple

class CyberDefenseEnv(gym.Env):
    """Custom Gym environment for cyber defense simulation"""
    
    def __init__(self):
        super(CyberDefenseEnv, self).__init__()
        
        self.action_space = spaces.Discrete(5)
        
        self.observation_space = spaces.Box(
            low=0, high=1, shape=(10,), dtype=np.float32
        )
        
        self.state = None
        self.attack_intensity = 0.5
        self.detection_threshold = 0.5
        self.episode_length = 100
        self.current_step = 0
        self.total_attacks = 0
        self.detected_attacks = 0
        self.false_positives = 0
        
    def reset(self, seed=None, options=None):
        super().reset(seed=seed)
        
        self.state = np.random.rand(10).astype(np.float32)
        self.attack_intensity = np.random.uniform(0.3, 0.7)
        self.detection_threshold = 0.5
        self.current_step = 0
        self.total_attacks = 0
        self.detected_attacks = 0
        self.false_positives = 0
        
        return self.state, {}
    
    def step(self, action: int) -> Tuple[np.ndarray, float, bool, bool, Dict]:
        self.current_step += 1
        
        if action == 0:
            self.detection_threshold = max(0.1, self.detection_threshold - 0.1)
        elif action == 1:
            self.detection_threshold = min(0.9, self.detection_threshold + 0.1)
        elif action == 2:
            pass
        elif action == 3:
            self.detection_threshold = 0.3
        elif action == 4:
            self.detection_threshold = 0.7
        
        is_attack = np.random.rand() < self.attack_intensity
        
        if is_attack:
            self.total_attacks += 1
            attack_strength = np.random.uniform(0.5, 1.0)
            detected = attack_strength > self.detection_threshold
            
            if detected:
                self.detected_attacks += 1
                reward = 10.0
            else:
                reward = -20.0
        else:
            normal_score = np.random.uniform(0.0, 0.5)
            false_alarm = normal_score > self.detection_threshold
            
            if false_alarm:
                self.false_positives += 1
                reward = -5.0
            else:
                reward = 1.0
        
        detection_speed_bonus = (1.0 - self.detection_threshold) * 2.0
        reward += detection_speed_bonus
        
        self.state = np.random.rand(10).astype(np.float32)
        self.state[0] = self.attack_intensity
        self.state[1] = self.detection_threshold
        self.state[2] = float(is_attack)
        
        terminated = self.current_step >= self.episode_length
        truncated = False
        
        info = {
            'total_attacks': self.total_attacks,
            'detected_attacks': self.detected_attacks,
            'false_positives': self.false_positives,
            'detection_rate': self.detected_attacks / max(1, self.total_attacks)
        }
        
        return self.state, reward, terminated, truncated, info
