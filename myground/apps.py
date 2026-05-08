from django.apps import AppConfig
import threading
import os
import logging

logger = logging.getLogger(__name__)

class MygroundConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'myground'

    # def ready(self):
    #     # 🚨 Prevent scheduler from starting twice (runserver fix)
    #     if os.environ.get("RUN_MAIN") != "true":
    #         return

    #     def start_scheduler_thread():
    #         try:
    #             from .scheduler import start_scheduler
    #             start_scheduler()
    #             print("✅ AWS Scheduler started successfully")
    #         except Exception as e:
    #             logger.error(f"⚠️ AWS Scheduler failed to start: {e}", exc_info=True)

    #     # Slight delay to ensure DB is ready
    #     threading.Timer(2, start_scheduler_thread).start()
