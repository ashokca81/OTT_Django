import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ott_admin.settings')

app = Celery('ott_admin')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()

@app.task(bind=True, max_retries=3)
def debug_task(self):
    print(f'Request: {self.request!r}') 