# Generated manually

from django.db import migrations, models

class Migration(migrations.Migration):

    dependencies = [
        ('main_accounts', '0008_video_progress_percent'),
    ]

    operations = [
        migrations.AlterField(
            model_name='video',
            name='progress_percent',
            field=models.FloatField(default=0, help_text='Progress percentage of video processing'),
        ),
    ] 