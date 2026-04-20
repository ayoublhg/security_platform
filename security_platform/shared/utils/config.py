#!/usr/bin/env python3
"""
Configuration management for the Enterprise Security Platform
"""

import os
import json
import yaml
from typing import Dict, Any, Optional
from pathlib import Path
from dotenv import load_dotenv
import logging

logger = logging.getLogger(__name__)

class Config:
    """Configuration manager with environment variable support"""
    
    _instance = None
    _config = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load_config()
        return cls._instance
    
    def _load_config(self):
        """Load configuration from environment and files"""
        # Load .env file
        load_dotenv()
        
        # Database
        self._config['database'] = {
            'host': os.getenv('DB_HOST', 'postgres'),
            'port': int(os.getenv('DB_PORT', '5432')),
            'user': os.getenv('DB_USER', 'postgres'),
            'password': os.getenv('DB_PASSWORD', 'secure_password'),
            'name': os.getenv('DB_NAME', 'security_platform'),
            'pool_min_size': int(os.getenv('DB_POOL_MIN_SIZE', '5')),
            'pool_max_size': int(os.getenv('DB_POOL_MAX_SIZE', '20'))
        }
        
        # Redis
        self._config['redis'] = {
            'host': os.getenv('REDIS_HOST', 'redis'),
            'port': int(os.getenv('REDIS_PORT', '6379')),
            'db': int(os.getenv('REDIS_DB', '0')),
            'password': os.getenv('REDIS_PASSWORD', '')
        }
        
        # JWT
        self._config['jwt'] = {
            'secret': os.getenv('JWT_SECRET', 'change-this-in-production'),
            'algorithm': os.getenv('JWT_ALGORITHM', 'HS256'),
            'expiry_hours': int(os.getenv('JWT_EXPIRY_HOURS', '24'))
        }
        
        # API
        self._config['api'] = {
            'host': os.getenv('API_HOST', '0.0.0.0'),
            'port': int(os.getenv('API_PORT', '8080')),
            'debug': os.getenv('API_DEBUG', 'false').lower() == 'true',
            'cors_origins': os.getenv('CORS_ORIGINS', '*').split(',')
        }
        
        # Dashboard
        self._config['dashboard'] = {
            'host': os.getenv('DASHBOARD_HOST', '0.0.0.0'),
            'port': int(os.getenv('DASHBOARD_PORT', '5000')),
            'secret_key': os.getenv('DASHBOARD_SECRET', 'change-this-in-production')
        }
        
        # Integrations
        self._config['integrations'] = {
            'github_token': os.getenv('GITHUB_TOKEN', ''),
            'gitlab_token': os.getenv('GITLAB_TOKEN', ''),
            'gitlab_url': os.getenv('GITLAB_URL', 'https://gitlab.com'),
            'jira_url': os.getenv('JIRA_URL', ''),
            'jira_user': os.getenv('JIRA_USER', ''),
            'jira_token': os.getenv('JIRA_TOKEN', ''),
            'slack_webhook': os.getenv('SLACK_WEBHOOK_URL', ''),
            'teams_webhook': os.getenv('TEAMS_WEBHOOK_URL', ''),
            'nvd_api_key': os.getenv('NVD_API_KEY', ''),
            'snyk_token': os.getenv('SNYK_TOKEN', ''),
            'sonar_token': os.getenv('SONAR_TOKEN', '')
        }
        
        # Scanners
        self._config['scanners'] = {
            'timeout': int(os.getenv('SCANNER_TIMEOUT', '300')),
            'max_concurrent': int(os.getenv('MAX_CONCURRENT_SCANS', '10')),
            'enabled': os.getenv('ENABLED_SCANNERS', 'sast,sca,secrets,container,iac').split(',')
        }
        
        # Logging
        self._config['logging'] = {
            'level': os.getenv('LOG_LEVEL', 'INFO'),
            'format': os.getenv('LOG_FORMAT', 'json'),
            'file': os.getenv('LOG_FILE', '')
        }
        
        # Load config file if exists
        config_file = os.getenv('CONFIG_FILE', 'config.yml')
        if os.path.exists(config_file):
            self._load_config_file(config_file)
    
    def _load_config_file(self, path: str):
        """Load configuration from YAML file"""
        try:
            with open(path, 'r') as f:
                if path.endswith('.yml') or path.endswith('.yaml'):
                    file_config = yaml.safe_load(f)
                elif path.endswith('.json'):
                    file_config = json.load(f)
                else:
                    logger.warning(f"Unsupported config file format: {path}")
                    return
                
                # Deep merge
                self._config = self._deep_merge(self._config, file_config)
                logger.info(f"Loaded configuration from {path}")
                
        except Exception as e:
            logger.error(f"Failed to load config file {path}: {e}")
    
    def _deep_merge(self, base: Dict, override: Dict) -> Dict:
        """Deep merge two dictionaries"""
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by dot notation key"""
        keys = key.split('.')
        value = self._config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default
        
        return value
    
    def get_database_url(self) -> str:
        """Get database URL for asyncpg"""
        db = self._config['database']
        return f"postgresql://{db['user']}:{db['password']}@{db['host']}:{db['port']}/{db['name']}"
    
    def get_redis_url(self) -> str:
        """Get Redis URL"""
        redis = self._config['redis']
        if redis['password']:
            return f"redis://:{redis['password']}@{redis['host']}:{redis['port']}/{redis['db']}"
        return f"redis://{redis['host']}:{redis['port']}/{redis['db']}"
    
    def as_dict(self) -> Dict:
        """Get entire configuration as dictionary"""
        return self._config.copy()
    
    def to_env(self) -> Dict[str, str]:
        """Convert config to environment variables"""
        env = {}
        
        def flatten(prefix: str, obj: Any):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    new_prefix = f"{prefix}_{key.upper()}" if prefix else key.upper()
                    flatten(new_prefix, value)
            elif isinstance(obj, (list, tuple)):
                env[prefix] = ','.join(str(v) for v in obj)
            else:
                env[prefix] = str(obj)
        
        flatten('', self._config)
        return env

# Global config instance
config = Config()

def load_config() -> Config:
    """Load and return configuration"""
    return config