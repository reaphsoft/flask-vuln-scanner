# utils.py

import time
import logging
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def log_execution(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        logging.info(f"[START] {func.__name__} called with args={args}, kwargs={kwargs}")
        result = func(*args, **kwargs)
        elapsed = time.time() - start_time
        logging.info(f"[END] {func.__name__} completed in {elapsed:.2f}s")
        return result
    return wrapper



