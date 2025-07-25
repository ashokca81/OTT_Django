# Generated by Django 4.2.7 on 2025-06-08 18:05

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('main_accounts', '0002_walletwithdrawal_wallet'),
    ]

    operations = [
        migrations.CreateModel(
            name='BankAccount',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('bank_name', models.CharField(max_length=100)),
                ('account_number', models.CharField(max_length=50)),
                ('ifsc_code', models.CharField(max_length=20)),
                ('account_holder_name', models.CharField(max_length=100)),
                ('is_verified', models.BooleanField(default=False)),
                ('is_primary', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='WalletTransaction',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('transaction_type', models.CharField(choices=[('DEPOSIT', 'Deposit'), ('WITHDRAWAL', 'Withdrawal'), ('REFERRAL_BONUS', 'Referral Bonus'), ('REFUND', 'Refund')], max_length=20)),
                ('amount', models.DecimalField(decimal_places=2, max_digits=12)),
                ('status', models.CharField(choices=[('PENDING', 'Pending'), ('PROCESSING', 'Processing'), ('COMPLETED', 'Completed'), ('FAILED', 'Failed'), ('REJECTED', 'Rejected')], default='PENDING', max_length=20)),
                ('reference_id', models.CharField(max_length=100, unique=True)),
                ('description', models.TextField(blank=True)),
                ('processed_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('bank_account', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='main_accounts.bankaccount')),
                ('processed_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='processed_transactions', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='WithdrawalAuditLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('action', models.CharField(choices=[('STATUS_CHANGE', 'Status Change'), ('AMOUNT_CHANGE', 'Amount Change'), ('COMMENT_ADD', 'Comment Added'), ('DOCUMENT_ADD', 'Document Added'), ('VERIFICATION', 'Verification'), ('MANUAL_REVIEW', 'Manual Review')], max_length=50)),
                ('old_value', models.JSONField(blank=True, null=True)),
                ('new_value', models.JSONField(blank=True, null=True)),
                ('ip_address', models.GenericIPAddressField()),
                ('user_agent', models.TextField()),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('notes', models.TextField(blank=True)),
                ('performed_by', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
                ('transaction', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='main_accounts.wallettransaction')),
            ],
            options={
                'ordering': ['-timestamp'],
            },
        ),
        migrations.CreateModel(
            name='WithdrawalDocument',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('document_type', models.CharField(choices=[('ID_PROOF', 'ID Proof'), ('BANK_STATEMENT', 'Bank Statement'), ('SELFIE', 'Selfie with ID'), ('OTHER', 'Other Document')], max_length=50)),
                ('file', models.FileField(upload_to='withdrawal_docs/%Y/%m/')),
                ('uploaded_at', models.DateTimeField(auto_now_add=True)),
                ('verified', models.BooleanField(default=False)),
                ('verified_at', models.DateTimeField(null=True)),
                ('notes', models.TextField(blank=True)),
                ('transaction', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='main_accounts.wallettransaction')),
                ('uploaded_by', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
                ('verified_by', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='verified_documents', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='WithdrawalLimit',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user_type', models.CharField(max_length=50)),
                ('limit_type', models.CharField(choices=[('DAILY', 'Daily Limit'), ('WEEKLY', 'Weekly Limit'), ('MONTHLY', 'Monthly Limit'), ('PER_TRANSACTION', 'Per Transaction Limit')], max_length=20)),
                ('amount', models.DecimalField(decimal_places=2, max_digits=12)),
                ('requires_verification', models.BooleanField(default=False)),
                ('requires_documents', models.BooleanField(default=False)),
                ('active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('notes', models.TextField(blank=True)),
            ],
        ),
        migrations.CreateModel(
            name='WithdrawalRiskAssessment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('risk_level', models.CharField(choices=[('LOW', 'Low Risk'), ('MEDIUM', 'Medium Risk'), ('HIGH', 'High Risk')], max_length=10)),
                ('user_account_age', models.DurationField()),
                ('previous_successful_withdrawals', models.IntegerField()),
                ('total_withdrawal_amount_24h', models.DecimalField(decimal_places=2, max_digits=12)),
                ('unusual_ip_detected', models.BooleanField(default=False)),
                ('unusual_device_detected', models.BooleanField(default=False)),
                ('kyc_verified', models.BooleanField(default=False)),
                ('bank_account_age', models.DurationField()),
                ('assessment_timestamp', models.DateTimeField(auto_now_add=True)),
                ('last_updated', models.DateTimeField(auto_now=True)),
                ('notes', models.TextField(blank=True)),
                ('assessed_by', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
                ('transaction', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to='main_accounts.wallettransaction')),
            ],
        ),
        migrations.CreateModel(
            name='WithdrawalVerificationQueue',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('status', models.CharField(choices=[('PENDING', 'Pending'), ('IN_PROGRESS', 'In Progress'), ('APPROVED', 'Approved'), ('REJECTED', 'Rejected'), ('ESCALATED', 'Escalated')], default='PENDING', max_length=20)),
                ('priority', models.IntegerField(default=0)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('completed_at', models.DateTimeField(null=True)),
                ('verification_notes', models.TextField(blank=True)),
                ('required_documents', models.JSONField(default=list)),
                ('escalation_reason', models.TextField(blank=True)),
                ('processing_time', models.DurationField(null=True)),
                ('assigned_to', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='assigned_verifications', to=settings.AUTH_USER_MODEL)),
                ('transaction', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to='main_accounts.wallettransaction')),
            ],
            options={
                'ordering': ['-priority', 'created_at'],
            },
        ),
        migrations.RenameField(
            model_name='wallet',
            old_name='last_updated',
            new_name='updated_at',
        ),
        migrations.AlterField(
            model_name='wallet',
            name='balance',
            field=models.DecimalField(decimal_places=2, default=0, max_digits=12),
        ),
        migrations.AlterField(
            model_name='wallet',
            name='user',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
        migrations.DeleteModel(
            name='WalletWithdrawal',
        ),
        migrations.AddField(
            model_name='wallettransaction',
            name='wallet',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='main_accounts.wallet'),
        ),
    ]
