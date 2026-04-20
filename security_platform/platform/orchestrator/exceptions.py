#!/usr/bin/env python3
"""
Custom exceptions for the orchestrator module
"""

class OrchestratorError(Exception):
    """Base exception for orchestrator errors"""
    pass

class TenantNotFoundError(OrchestratorError):
    """Raised when tenant is not found"""
    pass

class ScannerNotFoundError(OrchestratorError):
    """Raised when scanner is not found"""
    pass

class ScanFailedError(OrchestratorError):
    """Raised when scan fails"""
    pass

class QueueFullError(OrchestratorError):
    """Raised when queue is full"""
    pass

class QuotaExceededError(OrchestratorError):
    """Raised when tenant exceeds quota"""
    pass

class RepositoryError(OrchestratorError):
    """Raised when repository operation fails"""
    pass

class TimeoutError(OrchestratorError):
    """Raised when operation times out"""
    pass