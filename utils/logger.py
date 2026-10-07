"""
Logging utility for NOVUS
Provides structured logging with context support
"""
import logging
import threading
from datetime import datetime
from functools import wraps


class NovusLogger:
    """
    Thread-safe logger compatible with formato estándar logging (%s, exc_info, etc.).
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._initialized = True
        self.logger = logging.getLogger('NOVUS')
        self.logger.setLevel(logging.INFO)

        if not self.logger.handlers:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            formatter = logging.Formatter(
                '%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S',
            )
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

    def _emit(self, level: str, message, *args, context=None, exc_info=False, **kwargs):
        if args:
            try:
                message = message % args
            except Exception:
                message = f"{message} {' '.join(str(a) for a in args)}"
        if context is not None:
            message = f"{message} | Context: {context}"
        getattr(self.logger, level)(message, exc_info=exc_info, **kwargs)

    def info(self, message, *args, context=None, **kwargs):
        self._emit("info", message, *args, context=context, **kwargs)

    def warning(self, message, *args, context=None, **kwargs):
        self._emit("warning", message, *args, context=context, **kwargs)

    def error(self, message, *args, context=None, exc_info=False, **kwargs):
        self._emit("error", message, *args, context=context, exc_info=exc_info, **kwargs)

    def debug(self, message, *args, context=None, **kwargs):
        self._emit("debug", message, *args, context=context, **kwargs)


def log_execution(func):
    """Decorator to log function execution"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        log = NovusLogger()
        log.info(f"Executing: {func.__name__}")
        try:
            result = func(*args, **kwargs)
            log.info(f"Completed: {func.__name__}")
            return result
        except Exception as e:
            log.error(f"Error in {func.__name__}: {str(e)}", exc_info=True)
            raise
    return wrapper


logger = NovusLogger()
