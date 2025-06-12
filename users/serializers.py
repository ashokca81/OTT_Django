from rest_framework import serializers
from .models import UserProfile, UserDevice, UserOTP, UserSubscription, UserActivity, Wallet, BankAccount, WalletTransaction

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = [
            'id', 'phone', 'first_name', 'last_name', 'email',
            'gender', 'date_of_birth', 'profile_picture', 'status',
            'state', 'district', 'constituency', 'mandal', 'village',
            'pincode', 'address', 'is_subscribed', 'subscription_start_date',
            'subscription_end_date', 'subscription_type', 'created_at',
            'updated_at', 'last_login', 'is_verified', 'verification_date'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

class UserDeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserDevice
        fields = '__all__'
        read_only_fields = ('created_at', 'last_active')

class UserOTPSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserOTP
        fields = '__all__'
        read_only_fields = ('created_at', 'expires_at')

class UserSubscriptionSerializer(serializers.ModelSerializer):
    days_remaining = serializers.SerializerMethodField()
    
    class Meta:
        model = UserSubscription
        fields = '__all__'
        read_only_fields = ('created_at', 'updated_at')
    
    def get_days_remaining(self, obj):
        if obj.is_active and not obj.is_expired():
            from django.utils import timezone
            now = timezone.now()
            remaining = obj.end_date - now
            return max(0, remaining.days)
        return 0

class UserActivitySerializer(serializers.ModelSerializer):
    class Meta:
        model = UserActivity
        fields = '__all__'
        read_only_fields = ('created_at',)

# Custom Serializers for specific operations
class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ('phone', 'first_name', 'last_name', 'email', 'state', 'district', 
                 'constituency', 'mandal', 'village', 'pincode', 'address')

class UserLoginSerializer(serializers.Serializer):
    phone = serializers.CharField(max_length=15)
    otp = serializers.CharField(max_length=4)

    def validate_phone(self, value):
        # Remove any non-digit characters
        phone = ''.join(filter(str.isdigit, value))
        
        # Validate Indian phone number
        if not phone or len(phone) != 10:
            raise serializers.ValidationError('Please enter a valid Indian mobile number')
        return phone

    def validate_otp(self, value):
        # Validate OTP format
        if not value.isdigit() or len(value) != 4:
            raise serializers.ValidationError('OTP must be 4 digits')
        return value

class UserProfileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ('first_name', 'last_name', 'email', 'gender', 'date_of_birth', 
                 'profile_picture', 'state', 'district', 'constituency', 'mandal', 
                 'village', 'pincode', 'address')
        read_only_fields = ('phone',)

class OTPRequestSerializer(serializers.Serializer):
    phone = serializers.CharField(max_length=15)
    otp_type = serializers.ChoiceField(choices=UserOTP.OTP_TYPE_CHOICES)

class OTPVerificationSerializer(serializers.Serializer):
    phone = serializers.CharField(max_length=15)
    otp = serializers.CharField(max_length=4)
    otp_type = serializers.ChoiceField(choices=UserOTP.OTP_TYPE_CHOICES)

class UserSubscriptionCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserSubscription
        fields = ('plan_name', 'plan_duration', 'amount', 'promo_code')

class DeviceRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserDevice
        fields = ('device_id', 'device_type', 'device_name', 'device_model', 
                 'os_version', 'app_version')

class BankAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = BankAccount
        fields = ['id', 'account_holder_name', 'account_number', 'ifsc_code', 'bank_name', 'is_primary', 'is_verified', 'created_at']
        read_only_fields = ['is_verified', 'created_at']

class WalletTransactionSerializer(serializers.ModelSerializer):
    bank_account_details = BankAccountSerializer(source='bank_account', read_only=True)

    class Meta:
        model = WalletTransaction
        fields = ['id', 'amount', 'transaction_type', 'status', 'reference_id', 'bank_account', 'bank_account_details', 'description', 'created_at']
        read_only_fields = ['status', 'reference_id', 'created_at']

class WalletSerializer(serializers.ModelSerializer):
    recent_transactions = serializers.SerializerMethodField()

    class Meta:
        model = Wallet
        fields = ['id', 'balance', 'created_at', 'updated_at', 'recent_transactions']
        read_only_fields = ['balance', 'created_at', 'updated_at']

    def get_recent_transactions(self, obj):
        recent_transactions = obj.transactions.order_by('-created_at')[:5]
        return WalletTransactionSerializer(recent_transactions, many=True).data 