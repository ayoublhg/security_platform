"""API routes for the gateway."""
from .scans import router as scans_router
from .tenants import router as tenants_router
from .findings import router as findings_router
from .reports import router as reports_router

__all__ = ['scans_router', 'tenants_router', 'findings_router', 'reports_router']