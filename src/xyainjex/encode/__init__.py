"""Payload encoding / obfuscation for filter and WAF evasion."""

from .engine import EncodeResult, EncodeVariant, encode

__all__ = [
    "encode",
    "EncodeResult",
    "EncodeVariant",
]
