from django.db import migrations
from decimal import Decimal

def add_default_bonus_levels(apps, schema_editor):
    ReferralBonus = apps.get_model('users', 'ReferralBonus')
    
    # Define default bonus levels
    default_levels = [
        {
            'level': 1,
            'amount': Decimal('10.00'),  # 10% of payment amount
            'description': 'Direct referral bonus - Level 1'
        },
        {
            'level': 2,
            'amount': Decimal('5.00'),   # 5% of payment amount
            'description': 'Indirect referral bonus - Level 2'
        },
        {
            'level': 3,
            'amount': Decimal('3.00'),   # 3% of payment amount
            'description': 'Indirect referral bonus - Level 3'
        }
    ]
    
    # Create bonus levels
    for level_data in default_levels:
        ReferralBonus.objects.create(**level_data)

def remove_default_bonus_levels(apps, schema_editor):
    ReferralBonus = apps.get_model('users', 'ReferralBonus')
    ReferralBonus.objects.all().delete()

class Migration(migrations.Migration):
    dependencies = [
        ('users', '0001_initial'),  # Replace with your actual previous migration
    ]

    operations = [
        migrations.RunPython(add_default_bonus_levels, remove_default_bonus_levels),
    ] 