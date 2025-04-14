import os
import logging
import logging.handlers
from datetime import datetime

VERBOSE = 15 
NOTICE = 25

def setup_logger(app_name, log_dir="logs", log_level=logging.INFO, enable_console=True):
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    logger = logging.getLogger()
    logger.setLevel(log_level)
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    logging.addLevelName(VERBOSE, "VERBOSE")
    logging.addLevelName(NOTICE, "NOTICE")
    log_file = os.path.join(log_dir, f"{app_name}.log")
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10*1024*1024, backupCount=5
    )
    error_file = os.path.join(log_dir, f"{app_name}_error.log")
    error_handler = logging.handlers.RotatingFileHandler(
        error_file, maxBytes=10*1024*1024, backupCount=5
    )
    error_handler.setLevel(logging.ERROR)
    file_formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    error_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    logger.addHandler(error_handler)
    if enable_console:
        console_handler = logging.StreamHandler()
        console_formatter = logging.Formatter(
            '%(levelname)s: %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
    logger.verbose = lambda msg, *args, **kwargs: logger.log(VERBOSE, msg, *args, **kwargs)
    logger.notice = lambda msg, *args, **kwargs: logger.log(NOTICE, msg, *args, **kwargs)
    
    logger.info(f"Système de journalisation configuré pour {app_name}")
    return logger

def get_logger(name=None):
    if name:
        return logging.getLogger(name)
    return logging.getLogger()

class LogContext:
    def __init__(self, logger, operation, **context_data):
        self.logger = logger
        self.operation = operation
        self.context_data = context_data
        self.start_time = None
        
    def __enter__(self):
        self.start_time = datetime.now()
        self.logger.info(f"DÉBUT: {self.operation}", extra={'data': self.context_data})
        return self.logger
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = (datetime.now() - self.start_time).total_seconds()
        
        if exc_type is not None:
            self.logger.error(
                f"ÉCHEC: {self.operation} après {duration:.2f}s - {exc_type.__name__}: {exc_val}",
                exc_info=(exc_type, exc_val, exc_tb),
                extra={'data': {**self.context_data, 'duration_seconds': duration}}
            )
        else:
            self.logger.info(
                f"FIN: {self.operation} terminé en {duration:.2f}s",
                extra={'data': {**self.context_data, 'duration_seconds': duration}}
            )
        
        return False
