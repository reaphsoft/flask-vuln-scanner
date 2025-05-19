from celery import Celery

celery_app = Celery(
    'scanner',
    broker='redis://redis:6379/0',
    backend='redis://redis:6379/0'
)

celery_app.conf.update(
    task_serializer='json',
    result_serializer='json',
    accept_content=['json']
)

def init_celery(app=None):
    if app is not None:
        celery_app.conf.update(app.config)
        TaskBase = celery_app.Task

        class ContextTask(TaskBase):
            def __call__(self, *args, **kwargs):
                with app.app_context():
                    return TaskBase.__call__(self, *args, **kwargs)

        celery_app.Task = ContextTask




