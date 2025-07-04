# Generated by Django 4.2.7 on 2025-06-10 08:05

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('main_accounts', '0009_alter_video_progress_percent'),
    ]

    operations = [
        migrations.RenameField(
            model_name='video',
            old_name='processing_error',
            new_name='error_message',
        ),
        migrations.RemoveField(
            model_name='video',
            name='is_processed',
        ),
        migrations.RemoveField(
            model_name='video',
            name='processing_status',
        ),
        migrations.RemoveField(
            model_name='video',
            name='progress_percent',
        ),
        migrations.AddField(
            model_name='video',
            name='status',
            field=models.CharField(choices=[('uploading', 'Uploading'), ('processing', 'Processing'), ('ready', 'Ready'), ('failed', 'Failed')], default='uploading', max_length=20),
        ),
        migrations.AlterField(
            model_name='video',
            name='category',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='main_accounts.category'),
        ),
        migrations.AlterField(
            model_name='video',
            name='duration',
            field=models.IntegerField(default=0, help_text='Duration in seconds'),
        ),
        migrations.AlterField(
            model_name='video',
            name='hls_url',
            field=models.URLField(blank=True, max_length=500, null=True),
        ),
        migrations.AlterField(
            model_name='video',
            name='release_date',
            field=models.DateField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='video',
            name='video_type',
            field=models.CharField(choices=[('free', 'Free'), ('paid', 'Paid'), ('rental', 'Rental')], default='free', max_length=10),
        ),
    ]
