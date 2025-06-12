from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
from django.core.validators import MinValueValidator
from decimal import Decimal

class UserProfile(models.Model):
    GENDER_CHOICES = [
        ('M', 'Male'),
        ('F', 'Female'),
        ('O', 'Other')
    ]

    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('blocked', 'Blocked')
    ]

    phone = models.CharField(max_length=15, unique=True)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True, null=True, blank=True)
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES, null=True, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    profile_picture = models.ImageField(upload_to='profile_pictures/', null=True, blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='active')
    
    # Location details
    state = models.CharField(max_length=100)
    district = models.CharField(max_length=100)
    constituency = models.CharField(max_length=100)
    mandal = models.CharField(max_length=100)
    village = models.CharField(max_length=100)
    pincode = models.CharField(max_length=6)
    address = models.TextField()

    # Subscription details
    is_subscribed = models.BooleanField(default=False)
    subscription_start_date = models.DateTimeField(null=True, blank=True)
    subscription_end_date = models.DateTimeField(null=True, blank=True)
    subscription_type = models.CharField(max_length=50, null=True, blank=True)

    # System fields
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login = models.DateTimeField(null=True, blank=True)
    is_verified = models.BooleanField(default=False)
    verification_date = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'user_profiles'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.phone})"
    
    def update_last_login(self):
        self.last_login = timezone.now()
        self.save()

class UserDevice(models.Model):
    DEVICE_TYPE_CHOICES = [
        ('mobile', 'Mobile'),
        ('tablet', 'Tablet'),
        ('web', 'Web Browser'),
        ('tv', 'Smart TV'),
        ('other', 'Other')
    ]

    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name='devices')
    device_id = models.CharField(max_length=255)
    device_type = models.CharField(max_length=20, choices=DEVICE_TYPE_CHOICES)
    device_name = models.CharField(max_length=100)
    device_model = models.CharField(max_length=100, null=True, blank=True)
    os_version = models.CharField(max_length=50, null=True, blank=True)
    app_version = models.CharField(max_length=20, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    last_active = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'user_devices'
        unique_together = ['user', 'device_id']
        ordering = ['-last_active']

    def __str__(self):
        return f"{self.user.phone} - {self.device_name}"

class UserOTP(models.Model):
    OTP_TYPE_CHOICES = [
        ('login', 'Login'),
        ('register', 'Registration'),
        ('reset', 'Reset'),
        ('verify', 'Verification')
    ]

    phone = models.CharField(max_length=15)
    otp = models.CharField(max_length=4)
    otp_type = models.CharField(max_length=10, choices=OTP_TYPE_CHOICES)
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    attempts = models.IntegerField(default=0)

    class Meta:
        db_table = 'user_otps'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.phone} - {self.otp_type} OTP"

    def is_valid(self):
        now = timezone.now()
        return not self.is_used and now <= self.expires_at and self.attempts < 3

class UserSubscription(models.Model):
    PAYMENT_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('success', 'Success'),
        ('failed', 'Failed'),
        ('refunded', 'Refunded')
    ]

    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name='subscriptions')
    plan_name = models.CharField(max_length=100)
    plan_duration = models.IntegerField(help_text='Duration in days')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_id = models.CharField(max_length=100, null=True, blank=True)
    payment_status = models.CharField(max_length=10, choices=PAYMENT_STATUS_CHOICES, default='pending')
    start_date = models.DateTimeField()
    end_date = models.DateTimeField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Additional subscription details
    is_auto_renewal = models.BooleanField(default=False)
    cancelled_at = models.DateTimeField(null=True, blank=True)
    cancellation_reason = models.TextField(null=True, blank=True)
    promo_code = models.CharField(max_length=50, null=True, blank=True)
    discount_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)

    class Meta:
        db_table = 'user_subscriptions'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.phone} - {self.plan_name}"

    def is_expired(self):
        return timezone.now() > self.end_date

class UserActivity(models.Model):
    ACTIVITY_TYPE_CHOICES = [
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('subscription', 'Subscription'),
        ('profile_update', 'Profile Update'),
        ('password_reset', 'Password Reset'),
        ('device_added', 'Device Added'),
        ('device_removed', 'Device Removed')
    ]

    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name='activities')
    activity_type = models.CharField(max_length=20, choices=ACTIVITY_TYPE_CHOICES)
    device = models.ForeignKey(UserDevice, on_delete=models.SET_NULL, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    location = models.CharField(max_length=255, null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    details = models.JSONField(null=True, blank=True)

    class Meta:
        db_table = 'user_activities'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.phone} - {self.activity_type}"

class ReferralSystem(models.Model):
    user = models.OneToOneField(UserProfile, on_delete=models.CASCADE, related_name='referral')
    referral_code = models.CharField(max_length=10, unique=True)
    qr_code = models.ImageField(upload_to='referral_qr_codes/', null=True, blank=True)
    total_referrals = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'user_referrals'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.phone} - {self.referral_code}"

    @classmethod
    def generate_unique_referral_code(cls, user):
        """
        Generates a unique referral code for the user based on their phone number
        Format: All 10 digits of phone number
        """
        # Get all 10 digits of phone number
        phone = user.phone
        if phone.startswith('+91'):
            phone = phone[3:]  # Remove +91 if present
        
        # Ensure we have exactly 10 digits
        if len(phone) != 10:
            raise ValueError("Phone number must be 10 digits")
            
        return phone  # Return all 10 digits as referral code

    def save(self, *args, **kwargs):
        # Generate referral code if it doesn't exist
        if not self.referral_code:
            self.referral_code = self.generate_unique_referral_code(self.user)
        
        # Generate QR code if it doesn't exist
        if not self.qr_code:
            self.generate_qr_code()
            
        super().save(*args, **kwargs)

    def generate_qr_code(self):
        import qrcode
        import os
        from django.conf import settings
        
        # Create QR code instance
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        
        # Add the data (referral code and any additional info)
        qr_data = {
            "referral_code": self.referral_code,
            "referred_by": self.user.phone
        }
        qr.add_data(str(qr_data))
        qr.make(fit=True)

        # Create QR code image
        qr_image = qr.make_image(fill_color="black", back_color="white")
        
        # Save path
        file_name = f"referral_qr_{self.referral_code}.png"
        path = os.path.join('referral_qr_codes', file_name)
        full_path = os.path.join(settings.MEDIA_ROOT, path)
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        
        # Save QR code image
        qr_image.save(full_path)
        self.qr_code = path

class ReferralBonus(models.Model):
    """
    Stores the bonus amounts for each referral level
    """
    level = models.IntegerField(unique=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    description = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'referral_bonus_levels'
        ordering = ['level']

    def __str__(self):
        return f"Level {self.level}: ₹{self.amount}"

class ReferralTransaction(models.Model):
    """
    Records all referral bonus transactions
    """
    TRANSACTION_TYPES = [
        ('referral', 'Referral Bonus'),
        ('commission', 'Level Commission'),
    ]

    referrer = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name='referral_earnings', null=True, blank=True)
    referred_user = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name='referral_source', null=True, blank=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    level = models.IntegerField()
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPES, default='referral')
    status = models.CharField(max_length=20, default='pending')
    processed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    description = models.TextField(null=True, blank=True)

    class Meta:
        db_table = 'referral_transactions'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.referrer.phone} earned ₹{self.amount} from {self.referred_user.phone}"

    @classmethod
    def process_referral(cls, referred_user, referral_code):
        """
        Process referral bonus for 5 levels up from the referred user
        """
        try:
            # Find the direct referrer
            referral = ReferralSystem.objects.get(referral_code=referral_code)
            current_user = referral.user
            level = 1
            max_levels = 5

            while current_user and level <= max_levels:
                # Get bonus amount for this level
                try:
                    bonus = ReferralBonus.objects.get(level=level, is_active=True)
                except ReferralBonus.DoesNotExist:
                    break

                # Create transaction
                transaction = cls.objects.create(
                    referrer=current_user,
                    referred_user=referred_user,
                    amount=bonus.amount,
                    level=level,
                    transaction_type='commission' if level > 1 else 'referral',
                    status='completed',
                    processed_at=timezone.now(),
                    description=f"Level {level} {bonus.description}"
                )

                # Find next level referrer
                try:
                    current_user = ReferralRelationship.objects.get(
                        referee=current_user
                    ).referrer
                except ReferralRelationship.DoesNotExist:
                    break

                level += 1

            return True
        except Exception as e:
            print(f"Error processing referral: {str(e)}")
            return False

class ReferralRelationship(models.Model):
    referrer = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name='referrals_made')
    referee = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name='referred_by')
    referral_code_used = models.CharField(max_length=10)
    created_at = models.DateTimeField(auto_now_add=True)
    is_converted = models.BooleanField(default=False)  # Track if the referred user completed registration
    converted_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'user_referral_relationships'
        ordering = ['-created_at']
        unique_together = ['referrer', 'referee']  # Prevent duplicate relationships

    def __str__(self):
        return f"{self.referrer.phone} referred {self.referee.phone}"

    def save(self, *args, **kwargs):
        # If this is a new relationship and is_converted is True
        if not self.pk and self.is_converted:
            self.converted_at = timezone.now()
            # Increment the referrer's total_referrals count
            referral_system = self.referrer.referral
            referral_system.total_referrals += 1
            referral_system.save()
        super().save(*args, **kwargs)

class PaymentOrder(models.Model):
    order_id = models.CharField(max_length=100, unique=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=3, default='INR')
    plan_id = models.CharField(max_length=50, default='premium_365')
    status = models.CharField(max_length=20, default='created')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.order_id} - {self.amount} {self.currency}"

class PaymentTransaction(models.Model):
    order = models.ForeignKey(PaymentOrder, on_delete=models.CASCADE)
    payment_id = models.CharField(max_length=100)
    signature = models.CharField(max_length=255)
    status = models.CharField(max_length=20)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.payment_id} - {self.status}"

class Wallet(models.Model):
    user = models.OneToOneField(UserProfile, on_delete=models.CASCADE, related_name='wallet')
    balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.00, validators=[MinValueValidator(Decimal('0.00'))])
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.phone}'s Wallet (₹{self.balance})"

class BankAccount(models.Model):
    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name='bank_accounts')
    account_holder_name = models.CharField(max_length=100)
    account_number = models.CharField(max_length=20)
    ifsc_code = models.CharField(max_length=11)
    bank_name = models.CharField(max_length=100)
    is_primary = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ['user', 'account_number']

    def __str__(self):
        return f"{self.account_holder_name} - {self.bank_name}"

    def save(self, *args, **kwargs):
        if self.is_primary:
            # Set all other accounts of this user as non-primary
            BankAccount.objects.filter(user=self.user).update(is_primary=False)
        super().save(*args, **kwargs)

class WalletTransaction(models.Model):
    TRANSACTION_TYPES = [
        ('REFERRAL_BONUS', 'Referral Bonus'),
        ('WITHDRAWAL', 'Withdrawal'),
        ('REFUND', 'Refund'),
    ]

    TRANSACTION_STATUS = [
        ('PENDING', 'Pending'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
        ('CANCELLED', 'Cancelled'),
    ]

    # Constants for withdrawal limits - Default values
    MIN_WITHDRAWAL_AMOUNT = 20
    MAX_WITHDRAWAL_AMOUNT = 10000
    MAX_DAILY_WITHDRAWALS = 3

    wallet = models.ForeignKey(Wallet, on_delete=models.CASCADE, related_name='transactions')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPES)
    status = models.CharField(max_length=20, choices=TRANSACTION_STATUS, default='PENDING')
    reference_id = models.CharField(max_length=100, unique=True)
    bank_account = models.ForeignKey(BankAccount, on_delete=models.SET_NULL, null=True, blank=True)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.transaction_type} - ₹{self.amount} - {self.status}"

    @classmethod
    def get_daily_withdrawal_count(cls, wallet):
        """Get the number of withdrawals made today for this wallet"""
        today = timezone.now().date()
        return cls.objects.filter(
            wallet=wallet,
            transaction_type='WITHDRAWAL',
            created_at__date=today
        ).count()

    @classmethod
    def validate_withdrawal(cls, wallet, amount):
        """Validate withdrawal amount and limits"""
        # Get current withdrawal settings
        settings = WithdrawalSettings.get_settings()
        
        if amount < settings.min_withdrawal_amount:
            raise ValueError(f'Minimum withdrawal amount is ₹{settings.min_withdrawal_amount}')
            
        if amount > settings.max_withdrawal_amount:
            raise ValueError(f'Maximum withdrawal amount is ₹{settings.max_withdrawal_amount}')
            
        if amount > wallet.balance:
            raise ValueError('Insufficient balance')
            
        daily_count = cls.get_daily_withdrawal_count(wallet)
        if daily_count >= settings.max_daily_withdrawals:
            raise ValueError(f'Maximum {settings.max_daily_withdrawals} withdrawals allowed per day')

class WithdrawalSettings(models.Model):
    """Model to store withdrawal settings"""
    min_withdrawal_amount = models.DecimalField(max_digits=10, decimal_places=2, default=20)
    max_withdrawal_amount = models.DecimalField(max_digits=10, decimal_places=2, default=10000)
    max_daily_withdrawals = models.IntegerField(default=3)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(UserProfile, on_delete=models.SET_NULL, null=True)

    class Meta:
        verbose_name = 'Withdrawal Settings'
        verbose_name_plural = 'Withdrawal Settings'

    def __str__(self):
        return f"Withdrawal Settings (Updated: {self.updated_at.strftime('%Y-%m-%d %H:%M:%S')})"

    @classmethod
    def get_settings(cls):
        """Get the current withdrawal settings"""
        settings = cls.objects.first()
        if not settings:
            settings = cls.objects.create()
        return settings
