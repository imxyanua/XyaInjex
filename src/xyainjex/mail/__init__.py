"""Email header / SMTP injection context and breakout analysis."""

from .analyzer import analyze_mail
from .balance import mail_balance
from .breakout import detect_mail_breakout, score_mail_risk
from .context import analyze_mail_context
from .mutation import mutate_mail

__all__ = [
    "analyze_mail",
    "mutate_mail",
    "mail_balance",
    "detect_mail_breakout",
    "score_mail_risk",
    "analyze_mail_context",
]
