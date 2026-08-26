"""Typed errors that are safe to present without raw target content."""


class EvalMeshError(Exception):
    """Base class for expected EvalMesh failures."""


class ConfigurationError(EvalMeshError):
    """The manifest, case file, or local policy is invalid."""


class AdapterError(EvalMeshError):
    """An adapter could not start or complete a target invocation."""


class ReporterError(EvalMeshError):
    """A finalized run could not be delivered to a reporter."""


class PrivacyError(EvalMeshError):
    """A requested capture or reporting policy is not safely authorized."""
