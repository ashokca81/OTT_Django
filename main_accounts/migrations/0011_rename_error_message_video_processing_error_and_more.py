# Generated by Django 4.2.7 on 2025-06-10 08:32

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('main_accounts', '0010_rename_processing_error_video_error_message_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='video',
            old_name='error_message',
            new_name='processing_error',
        ),
        migrations.RemoveField(
            model_name='video',
            name='status',
        ),
        migrations.AddField(
            model_name='video',
            name='is_processed',
            field=models.BooleanField(default=False, help_text='Whether video has been converted to HLS'),
        ),
        migrations.AddField(
            model_name='video',
            name='processing_status',
            field=models.CharField(choices=[('pending', 'Pending'), ('processing', 'Processing'), ('completed', 'Completed'), ('failed', 'Failed')], default='pending', max_length=20),
        ),
        migrations.AddField(
            model_name='video',
            name='progress_percent',
            field=models.FloatField(default=0, help_text='Progress percentage of video processing'),
        ),
        migrations.AlterField(
            model_name='video',
            name='category',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='videos', to='main_accounts.category'),
        ),
        migrations.AlterField(
            model_name='video',
            name='duration',
            field=models.IntegerField(help_text='Duration in seconds'),
        ),
        migrations.AlterField(
            model_name='video',
            name='hls_url',
            field=models.URLField(blank=True, help_text='URL to master HLS playlist', max_length=500, null=True),
        ),
        migrations.AlterField(
            model_name='video',
            name='release_date',
            field=models.DateField(),
        ),
        migrations.AlterField(
            model_name='video',
            name='video_type',
            field=models.CharField(choices=[('free', 'Free'), ('paid', 'Paid'), ('rental', 'Rental')], max_length=10),
        ),
    ]
