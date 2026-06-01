"""
Custom exceptions for CYS-ILM Reconnaissance Tool.
"""


class ReconError(Exception):
    """Base exception for all tool errors."""


class ValidationError(ReconError):
    """Raised when target validation fails."""


class PrivilegeError(ReconError):
    """Raised when root/sudo privileges are required."""


class ScanError(ReconError):
    """Raised when a scan operation fails."""


class ReportError(ReconError):
    """Raised when report generation fails."""


class NetworkError(ReconError):
    """Raised on unrecoverable network failures."""
