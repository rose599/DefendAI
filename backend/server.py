from fastapi import FastAPI, APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
import asyncio
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone
import json

from red_team.attack_simulator import AttackSimulator
from blue_team.ml_classifier import MLClassifier
from reinforcement.train_rl import RLTrainer

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

app = FastAPI()
api_router = APIRouter(prefix="/api")

attack_simulator = AttackSimulator()
ml_classifier = MLClassifier()
rl_trainer = RLTrainer()

class NetworkLog(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str
    source_ip: str
    destination_ip: str
    protocol: str
    packet_size: int
    port: int
    login_attempts: int
    flow_duration: float
    packets_per_second: float
    label: str
    attack_type: Optional[str] = None

class DetectionAlert(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    log_id: str
    source_ip: str
    destination_ip: str
    attack_type: str
    confidence: float
    severity: str

class ModelMetrics(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    training_time: float
    training_samples: int

class RLMetrics(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    episode: int
    reward: float
    avg_reward: float

class SimulationConfig(BaseModel):
    attack_types: Optional[List[str]] = None
    intensity: str = 'medium'

class TrainMLRequest(BaseModel):
    num_logs: int = 1000

class TrainRLRequest(BaseModel):
    timesteps: int = 10000

@api_router.get("/")
async def root():
    return {"message": "CyberDefense Simulation API"}

@api_router.post("/simulation/start")
async def start_simulation(config: SimulationConfig, background_tasks: BackgroundTasks):
    result = await attack_simulator.start_simulation(
        attack_types=config.attack_types,
        intensity=config.intensity
    )
    background_tasks.add_task(run_simulation_background)
    return result

async def run_simulation_background():
    while attack_simulator.is_running:
        logs = attack_simulator.generate_batch(batch_size=10, attack_ratio=0.3)
        
        for log in logs:
            log_dict = log.copy()
            await db.network_logs.insert_one(log_dict)
            
            if ml_classifier.is_trained:
                try:
                    predictions, probabilities, latency = ml_classifier.predict([log])
                    
                    if predictions[0] == 1:
                        alert = {
                            'id': str(uuid.uuid4()),
                            'timestamp': datetime.now(timezone.utc).isoformat(),
                            'log_id': log.get('id', ''),
                            'source_ip': log['source_ip'],
                            'destination_ip': log['destination_ip'],
                            'attack_type': log.get('attack_type', 'Unknown'),
                            'confidence': probabilities[0],
                            'severity': 'high' if probabilities[0] > 0.8 else 'medium'
                        }
                        await db.detection_alerts.insert_one(alert)
                except Exception as e:
                    logging.error(f"Detection error: {e}")
        
        await asyncio.sleep(1.0)

@api_router.post("/simulation/stop")
async def stop_simulation():
    result = attack_simulator.stop_simulation()
    return result

@api_router.get("/simulation/status")
async def get_simulation_status():
    return attack_simulator.get_status()

@api_router.get("/logs")
async def get_logs(limit: int = 100):
    logs = await db.network_logs.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit).to_list(limit)
    return logs

@api_router.get("/alerts")
async def get_alerts(limit: int = 50):
    alerts = await db.detection_alerts.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit).to_list(limit)
    return alerts

@api_router.post("/ml/train")
async def train_ml_model(request: TrainMLRequest):
    logs = attack_simulator.generate_batch(batch_size=request.num_logs, attack_ratio=0.3)
    
    for log in logs:
        await db.network_logs.insert_one(log)
    
    metrics = ml_classifier.train(logs)
    
    if 'error' not in metrics:
        metrics_doc = {
            'id': str(uuid.uuid4()),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            **metrics
        }
        await db.model_metrics.insert_one(metrics_doc)
    
    return metrics

@api_router.get("/ml/metrics")
async def get_ml_metrics():
    return ml_classifier.get_metrics()

@api_router.post("/rl/train")
async def train_rl_agent(request: TrainRLRequest, background_tasks: BackgroundTasks):
    background_tasks.add_task(train_rl_background, request.timesteps)
    return {"status": "training_started", "timesteps": request.timesteps}

async def train_rl_background(timesteps: int):
    metrics = rl_trainer.train(total_timesteps=timesteps)
    
    for i, reward in enumerate(metrics.get('episode_rewards', [])):
        rl_metrics_doc = {
            'id': str(uuid.uuid4()),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'episode': i,
            'reward': reward,
            'avg_reward': metrics['avg_rewards'][i] if i < len(metrics['avg_rewards']) else reward
        }
        await db.rl_metrics.insert_one(rl_metrics_doc)

@api_router.get("/rl/metrics")
async def get_rl_metrics(limit: int = 100):
    metrics = await db.rl_metrics.find({}, {"_id": 0}).sort("episode", -1).limit(limit).to_list(limit)
    return metrics

@api_router.get("/dashboard/stats")
async def get_dashboard_stats():
    total_logs = await db.network_logs.count_documents({})
    total_alerts = await db.detection_alerts.count_documents({})
    
    malicious_logs = await db.network_logs.count_documents({"label": "malicious"})
    
    recent_logs = await db.network_logs.find({}, {"_id": 0}).sort("timestamp", -1).limit(100).to_list(100)
    attack_types_count = {}
    for log in recent_logs:
        if log.get('attack_type'):
            attack_types_count[log['attack_type']] = attack_types_count.get(log['attack_type'], 0) + 1
    
    return {
        'total_logs': total_logs,
        'total_alerts': total_alerts,
        'malicious_logs': malicious_logs,
        'attack_distribution': attack_types_count,
        'simulation_status': attack_simulator.get_status(),
        'ml_trained': ml_classifier.is_trained,
        'rl_trained': rl_trainer.is_trained
    }

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()