from celery_app import celery_app
from scanner import perform_scan  # Make sure perform_scan(target) exists in scanner.py

@celery_app.task(name='run_scan_task')
def run_scan_task(target):
    try:
        result = perform_scan(target)
        return {
            "status": "success",
            "data": result
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }




