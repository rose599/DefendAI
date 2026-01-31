from stable_baselines3 import PPO
from stable_baselines3.common.callbacks import BaseCallback
import numpy as np
from typing import List, Dict
from .rl_env import CyberDefenseEnv
import os

class MetricsCallback(BaseCallback):
    """Callback to track training metrics"""
    
    def __init__(self, verbose=0):
        super(MetricsCallback, self).__init__(verbose)
        self.episode_rewards = []
        self.episode_lengths = []
        self.detection_rates = []
        
    def _on_step(self) -> bool:
        if 'episode' in self.locals.get('infos', [{}])[0]:
            info = self.locals['infos'][0]['episode']
            self.episode_rewards.append(info['r'])
            self.episode_lengths.append(info['l'])
        return True

class RLTrainer:
    """Reinforcement Learning trainer for cyber defense"""
    
    def __init__(self):
        self.env = CyberDefenseEnv()
        self.model = None
        self.is_trained = False
        self.training_metrics = {
            'episode_rewards': [],
            'avg_rewards': [],
            'episodes_completed': 0
        }
        
    def train(self, total_timesteps: int = 10000) -> Dict:
        """Train the RL agent"""
        self.model = PPO(
            'MlpPolicy',
            self.env,
            verbose=0,
            learning_rate=0.0003,
            n_steps=2048,
            batch_size=64,
            n_epochs=10,
            gamma=0.99
        )
        
        callback = MetricsCallback()
        self.model.learn(total_timesteps=total_timesteps, callback=callback, progress_bar=False)
        
        self.is_trained = True
        
        self.training_metrics = {
            'episode_rewards': callback.episode_rewards,
            'avg_rewards': [np.mean(callback.episode_rewards[max(0, i-10):i+1]) 
                          for i in range(len(callback.episode_rewards))],
            'episodes_completed': len(callback.episode_rewards),
            'total_timesteps': total_timesteps
        }
        
        return self.training_metrics
    
    def evaluate(self, n_episodes: int = 10) -> Dict:
        """Evaluate the trained agent"""
        if not self.is_trained:
            return {'error': 'Model not trained yet'}
        
        episode_rewards = []
        detection_rates = []
        
        for _ in range(n_episodes):
            obs, _ = self.env.reset()
            episode_reward = 0
            done = False
            
            while not done:
                action, _ = self.model.predict(obs, deterministic=True)
                obs, reward, terminated, truncated, info = self.env.step(action)
                episode_reward += reward
                done = terminated or truncated
            
            episode_rewards.append(episode_reward)
            detection_rates.append(info['detection_rate'])
        
        return {
            'avg_reward': float(np.mean(episode_rewards)),
            'std_reward': float(np.std(episode_rewards)),
            'avg_detection_rate': float(np.mean(detection_rates)),
            'episodes_evaluated': n_episodes
        }
    
    def get_metrics(self) -> Dict:
        """Get training metrics"""
        return self.training_metrics
    
    def save_model(self, filepath: str):
        """Save trained model"""
        if self.model:
            self.model.save(filepath)
    
    def load_model(self, filepath: str):
        """Load trained model"""
        if os.path.exists(filepath + '.zip'):
            self.model = PPO.load(filepath, env=self.env)
            self.is_trained = True
