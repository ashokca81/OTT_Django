from django.shortcuts import render
from rest_framework import viewsets, status, generics
from rest_framework.decorators import action, api_view, permission_classes, authentication_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authentication import SessionAuthentication
from django.utils import timezone
from datetime import timedelta
import random
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model, login, authenticate
from django.middleware.csrf import get_token
from rest_framework_simplejwt.authentication import JWTAuthentication
import uuid
import json
import requests
import hmac
import hashlib
import base64
from django.conf import settings
import razorpay
from django.db.models import Sum
from django.db import transaction
from decimal import Decimal
from rest_framework import serializers

from .models import (
    UserProfile, UserDevice, UserOTP, 
    UserSubscription, UserActivity, ReferralSystem,
    ReferralRelationship, PaymentOrder, PaymentTransaction,
    ReferralBonus, ReferralTransaction, Wallet, BankAccount, WalletTransaction,
    WithdrawalSettings
)
from .serializers import (
    UserProfileSerializer, UserDeviceSerializer,
    UserOTPSerializer, UserSubscriptionSerializer,
    UserActivitySerializer, UserRegistrationSerializer,
    UserLoginSerializer, UserProfileUpdateSerializer,
    OTPRequestSerializer, OTPVerificationSerializer,
    UserSubscriptionCreateSerializer, DeviceRegistrationSerializer,
    WalletSerializer, BankAccountSerializer, WalletTransactionSerializer
)
from .utils import OTPService

User = get_user_model()

@method_decorator(csrf_exempt, name='dispatch')
class UserViewSet(viewsets.ModelViewSet):
    queryset = UserProfile.objects.all()
    serializer_class = UserProfileSerializer
    permission_classes = [AllowAny]
    authentication_classes = []
    otp_service = OTPService()

    def get_permissions(self):
        if self.action in ['request_otp', 'verify_otp', 'login', 'complete_registration', 'get_profile', 'update_profile', 'get_devices_info', 'add_device', 'deactivate_device']:
            return [AllowAny()]
        return [IsAuthenticated()]

    def get_serializer_class(self):
        if self.action == 'create':
            return UserRegistrationSerializer
        elif self.action == 'update' or self.action == 'partial_update':
            return UserProfileUpdateSerializer
        return self.serializer_class

    @action(detail=False, methods=['post'], url_path='request-otp', permission_classes=[AllowAny])
    def request_otp(self, request):
        serializer = OTPRequestSerializer(data=request.data)
        if serializer.is_valid():
            phone = serializer.validated_data['phone']
            otp_type = serializer.validated_data['otp_type']
            
            # Generate OTP
            otp = ''.join(random.choices('0123456789', k=4))
            expires_at = timezone.now() + timedelta(minutes=10)
            
            # Send OTP using MSG91
            success, message = self.otp_service.send_otp(phone, otp)
            
            if success:
                # Save OTP in database
                UserOTP.objects.create(
                    phone=phone,
                    otp=otp,
                    otp_type=otp_type,
                    expires_at=expires_at
                )
                
                return Response({
                    'message': 'OTP sent successfully',
                    'phone': phone
                })
            else:
                return Response({
                    'message': message
                }, status=status.HTTP_400_BAD_REQUEST)
                
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'], url_path='verify-otp', permission_classes=[AllowAny])
    def verify_otp(self, request):
        serializer = OTPVerificationSerializer(data=request.data)
        if serializer.is_valid():
            phone = serializer.validated_data['phone']
            otp = serializer.validated_data['otp']
            otp_type = serializer.validated_data['otp_type']
            
            # Get latest OTP
            user_otp = UserOTP.objects.filter(
                phone=phone,
                otp_type=otp_type,
                is_used=False
            ).order_by('-created_at').first()
            
            if not user_otp:
                return Response({
                    'message': 'No OTP found'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            if not user_otp.is_valid():
                return Response({
                    'message': 'OTP expired or too many attempts'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Verify OTP using MSG91
            success, message = self.otp_service.verify_otp(phone, otp)
            
            if not success:
                user_otp.attempts += 1
                user_otp.save()
                return Response({
                    'message': message
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Mark OTP as used
            user_otp.is_used = True
            user_otp.save()
            
            # If registration OTP, create user profile
            if otp_type == 'register':
                user, created = UserProfile.objects.get_or_create(
                    phone=phone,
                    defaults={'is_verified': True}
                )
                serializer = UserProfileSerializer(user)
                return Response(serializer.data)
            
            return Response({
                'message': 'OTP verified successfully'
            })
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def handle_device_management(self, user, request_data):
        """
        Handle device management for a user
        """
        try:
            device_id = request_data.get('device_id')
            if not device_id:
                # Generate a unique device ID if not provided
                device_id = str(uuid.uuid4())

            # Get device details
            device_name = request_data.get('device_name', 'Unknown Device')
            device_type = request_data.get('device_type', 'other')
            device_model = request_data.get('device_model', '')
            os_version = request_data.get('os_version', '')
            app_version = request_data.get('app_version', '')

            # Check active devices count
            active_devices = UserDevice.objects.filter(user=user, is_active=True)
            active_count = active_devices.count()

            # If device already exists, update it
            existing_device = UserDevice.objects.filter(user=user, device_id=device_id).first()
            if existing_device:
                existing_device.device_name = device_name
                existing_device.device_type = device_type
                existing_device.device_model = device_model
                existing_device.os_version = os_version
                existing_device.app_version = app_version
                existing_device.is_active = True
                existing_device.save()
                return existing_device, active_count

            # If max devices reached, deactivate oldest device
            if active_count >= 3:
                oldest_device = active_devices.order_by('last_active').first()
                if oldest_device:
                    oldest_device.is_active = False
                    oldest_device.save()

            # Create new device
            new_device = UserDevice.objects.create(
                user=user,
                device_id=device_id,
                device_type=device_type,
                device_name=device_name,
                device_model=device_model,
                os_version=os_version,
                app_version=app_version,
                is_active=True
            )
            return new_device, active_count + 1
        except Exception as e:
            print(f"Error in handle_device_management: {str(e)}")
            return None, 0

    @action(detail=False, methods=['post'], url_path='login', permission_classes=[AllowAny])
    def login(self, request):
        try:
            serializer = UserLoginSerializer(data=request.data)
            if serializer.is_valid():
                phone = serializer.validated_data['phone']
                otp = serializer.validated_data['otp']
                
                # Get or create user
                user, created = UserProfile.objects.get_or_create(
                    phone=phone,
                    defaults={'is_verified': True}
                )
                
                # Verify OTP
                user_otp = UserOTP.objects.filter(
                    phone=phone,
                    otp_type='login',
                    is_used=False
                ).order_by('-created_at').first()
                
                if not user_otp:
                    return Response({
                        'status': 'error',
                        'message': 'No OTP found'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                if not user_otp.is_valid():
                    return Response({
                        'status': 'error',
                        'message': 'OTP expired or too many attempts'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                if user_otp.otp != otp:
                    return Response({
                        'status': 'error',
                        'message': 'Invalid OTP'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                # Mark OTP as used
                user_otp.is_used = True
                user_otp.save()
                
                # Update last login
                user.update_last_login()
                
                # Handle device management
                device, active_devices_count = self.handle_device_management(user, request.data)
                
                # Create activity log
                UserActivity.objects.create(
                    user=user,
                    activity_type='login',
                    device=device,
                    ip_address=request.META.get('REMOTE_ADDR'),
                    user_agent=request.META.get('HTTP_USER_AGENT')
                )
                
                # Create session
                login(request, user)
                
                # Get CSRF token
                csrf_token = get_token(request)
                
                response_data = {
                    'status': 'success',
                    'message': 'Login successful',
                    'user': UserProfileSerializer(user).data,
                    'csrf_token': csrf_token,
                    'device': {
                        'id': device.id if device else None,
                        'device_id': device.device_id if device else None,
                        'device_name': device.device_name if device else None,
                        'device_type': device.get_device_type_display() if device else None,
                        'is_active': device.is_active if device else None
                    } if device else None,
                    'active_devices': active_devices_count,
                    'max_devices_allowed': 3
                }
                
                response = Response(response_data)
                response['X-CSRFToken'] = csrf_token
                return response
                
            return Response({
                'status': 'error',
                'message': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['post'], url_path='complete-registration', permission_classes=[AllowAny])
    def complete_registration(self, request):
        phone = request.data.get('phone')
        profile_data = request.data
        referral_code = profile_data.get('referral_code')
        
        try:
            user_profile = UserProfile.objects.get(phone=phone)
            
            # Update user profile with registration data
            serializer = UserRegistrationSerializer(user_profile, data=profile_data, partial=True)
            if serializer.is_valid():
                try:
                    user_profile = serializer.save()
                    user_profile.is_verified = True
                    user_profile.save()
                    
                    # Generate referral code automatically after registration
                    referral, created = ReferralSystem.objects.get_or_create(
                        user=user_profile,
                        defaults={'referral_code': None}  # Will be auto-generated in save()
                    )

                    # Handle referral relationship if referral code was provided
                    if referral_code:
                        try:
                            referrer_system = ReferralSystem.objects.get(referral_code=referral_code)
                            # Create referral relationship
                            relationship, created = ReferralRelationship.objects.get_or_create(
                                referrer=referrer_system.user,
                                referee=user_profile,
                                defaults={
                                    'referral_code_used': referral_code,
                                    'is_converted': True
                                }
                            )
                            if not created:
                                # Update existing relationship if it exists
                                relationship.is_converted = True
                                relationship.converted_at = timezone.now()
                                relationship.save()
                        except ReferralSystem.DoesNotExist:
                            # Invalid referral code, but we'll still complete registration
                            pass
                    
                    # Create session
                    login(request, user_profile)
                    
                    # Get CSRF token
                    csrf_token = get_token(request)
                    
                    response_data = {
                        'status': 'success',
                        'message': 'Registration completed successfully',
                        'user': UserProfileSerializer(user_profile).data,
                        'referral_code': referral.referral_code,
                        'csrf_token': csrf_token
                    }
                    
                    response = Response(response_data)
                    response['X-CSRFToken'] = csrf_token
                    return response
                    
                except Exception as e:
                    return Response({
                        'status': 'error',
                        'message': str(e),
                        'code': 'registration_failed'
                    }, status=status.HTTP_400_BAD_REQUEST)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        except UserProfile.DoesNotExist:
            return Response({
                'status': 'error',
                'message': 'User not found',
                'code': 'user_not_found'
            }, status=status.HTTP_404_NOT_FOUND)
            
        except Exception as e:
            return Response({
                'status': 'error',
                'message': str(e),
                'code': 'unknown_error'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @method_decorator(csrf_exempt)
    @action(detail=False, methods=['get'], url_path='profile', permission_classes=[AllowAny])
    def get_profile(self, request):
        try:
            # Get phone from query params
            phone = request.query_params.get('phone')
            
            if not phone:
                return Response({
                    'status': 'error',
                    'message': 'Phone number is required'
                }, status=status.HTTP_400_BAD_REQUEST)

            try:
                user = UserProfile.objects.get(phone=phone)
                serializer = UserProfileSerializer(user)
                return Response({
                    'status': 'success',
                    'user': serializer.data
                })
            except UserProfile.DoesNotExist:
                return Response({
                    'status': 'error',
                    'message': 'User not found'
                }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    @method_decorator(csrf_exempt)
    @action(detail=False, methods=['post'], url_path='update-profile', permission_classes=[AllowAny])
    def update_profile(self, request):
        try:
            # Get phone from request data
            phone = request.data.get('phone')
            referral_code = request.data.get('referral_code')
            
            if not phone:
                return Response({
                    'status': 'error',
                    'message': 'Phone number is required'
                }, status=status.HTTP_400_BAD_REQUEST)

            try:
                user = UserProfile.objects.get(phone=phone)
            except UserProfile.DoesNotExist:
                return Response({
                    'status': 'error',
                    'message': 'User not found'
                }, status=status.HTTP_404_NOT_FOUND)

            serializer = UserProfileUpdateSerializer(user, data=request.data, partial=True)
            
            if serializer.is_valid():
                user = serializer.save()
                
                # Handle referral code if provided
                if referral_code:
                    try:
                        referrer_system = ReferralSystem.objects.get(referral_code=referral_code)
                        
                        # Don't allow self-referral
                        if referrer_system.user == user:
                            return Response({
                                'status': 'error',
                                'message': 'You cannot use your own referral code'
                            }, status=status.HTTP_400_BAD_REQUEST)
                            
                        # Create or update referral relationship
                        relationship, created = ReferralRelationship.objects.get_or_create(
                            referrer=referrer_system.user,
                            referee=user,
                            defaults={
                                'referral_code_used': referral_code,
                                'is_converted': True,
                                'converted_at': timezone.now()
                            }
                        )
                        
                        if not created:
                            # Update existing relationship
                            relationship.is_converted = True
                            relationship.converted_at = timezone.now()
                            relationship.save()
                            
                        # Increment referrer's total_referrals count if not already counted
                        if created or not relationship.is_converted:
                            referrer_system.total_referrals += 1
                            referrer_system.save()
                            
                    except ReferralSystem.DoesNotExist:
                        return Response({
                            'status': 'error',
                            'message': 'Invalid referral code'
                        }, status=status.HTTP_404_NOT_FOUND)
                
                # Create activity log
                UserActivity.objects.create(
                    user=user,
                    activity_type='profile_update',
                    ip_address=request.META.get('REMOTE_ADDR'),
                    user_agent=request.META.get('HTTP_USER_AGENT'),
                    details={'updated_fields': list(request.data.keys())}
                )
                
                return Response({
                    'status': 'success',
                    'message': 'Profile updated successfully',
                    'user': UserProfileSerializer(user).data
                })
            
            return Response({
                'status': 'error',
                'message': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    @method_decorator(csrf_exempt)
    @action(detail=False, methods=['get'], url_path='devices-info', permission_classes=[AllowAny])
    def get_devices_info(self, request):
        try:
            phone = request.query_params.get('phone')
            
            if not phone:
                return Response({
                    'status': 'error',
                    'message': 'Phone number is required'
                }, status=status.HTTP_400_BAD_REQUEST)

            try:
                user = UserProfile.objects.get(phone=phone)
                devices = UserDevice.objects.filter(user=user)
                
                device_info = []
                for device in devices:
                    device_info.append({
                        'id': device.id,
                        'device_name': device.device_name,
                        'device_type': device.get_device_type_display(),
                        'device_model': device.device_model,
                        'os_version': device.os_version,
                        'app_version': device.app_version,
                        'is_active': device.is_active,
                        'last_active': device.last_active,
                        'created_at': device.created_at
                    })
                
                return Response({
                    'status': 'success',
                    'devices': device_info,
                    'total_devices': len(device_info),
                    'active_devices': len([d for d in device_info if d['is_active']]),
                    'max_devices_allowed': 3  # You can make this configurable
                })
            except UserProfile.DoesNotExist:
                return Response({
                    'status': 'error',
                    'message': 'User not found'
                }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    @method_decorator(csrf_exempt)
    @action(detail=False, methods=['post'], url_path='add-device', permission_classes=[AllowAny])
    def add_device(self, request):
        try:
            phone = request.data.get('phone')
            device_data = request.data
            
            if not phone:
                return Response({
                    'status': 'error',
                    'message': 'Phone number is required'
                }, status=status.HTTP_400_BAD_REQUEST)

            try:
                user = UserProfile.objects.get(phone=phone)
                
                # Check if maximum devices limit reached
                active_devices = UserDevice.objects.filter(user=user, is_active=True).count()
                if active_devices >= 3:  # Maximum 3 devices allowed
                    return Response({
                        'status': 'error',
                        'message': 'Maximum device limit reached. Please deactivate an existing device.'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                # Create new device
                device = UserDevice.objects.create(
                    user=user,
                    device_id=device_data.get('device_id'),
                    device_type=device_data.get('device_type', 'other'),
                    device_name=device_data.get('device_name', 'Unknown Device'),
                    device_model=device_data.get('device_model'),
                    os_version=device_data.get('os_version'),
                    app_version=device_data.get('app_version')
                )
                
                # Log activity
                UserActivity.objects.create(
                    user=user,
                    activity_type='device_added',
                    device=device,
                    ip_address=request.META.get('REMOTE_ADDR'),
                    user_agent=request.META.get('HTTP_USER_AGENT')
                )
                
                return Response({
                    'status': 'success',
                    'message': 'Device added successfully',
                    'device': {
                        'id': device.id,
                        'device_name': device.device_name,
                        'device_type': device.get_device_type_display(),
                        'is_active': device.is_active
                    }
                })
                
            except UserProfile.DoesNotExist:
                return Response({
                    'status': 'error',
                    'message': 'User not found'
                }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    @method_decorator(csrf_exempt)
    @action(detail=False, methods=['post'], url_path='deactivate-device', permission_classes=[AllowAny])
    def deactivate_device(self, request):
        try:
            phone = request.data.get('phone')
            device_id = request.data.get('device_id')
            
            if not phone or not device_id:
                return Response({
                    'status': 'error',
                    'message': 'Phone number and device ID are required'
                }, status=status.HTTP_400_BAD_REQUEST)

            try:
                user = UserProfile.objects.get(phone=phone)
                device = UserDevice.objects.get(user=user, id=device_id)
                
                device.is_active = False
                device.save()
                
                # Log activity
                UserActivity.objects.create(
                    user=user,
                    activity_type='device_removed',
                    device=device,
                    ip_address=request.META.get('REMOTE_ADDR'),
                    user_agent=request.META.get('HTTP_USER_AGENT')
                )
                
                return Response({
                    'status': 'success',
                    'message': 'Device deactivated successfully'
                })
                
            except UserProfile.DoesNotExist:
                return Response({
                    'status': 'error',
                    'message': 'User not found'
                }, status=status.HTTP_404_NOT_FOUND)
            except UserDevice.DoesNotExist:
                return Response({
                    'status': 'error',
                    'message': 'Device not found'
                }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

class UserDeviceViewSet(viewsets.ModelViewSet):
    queryset = UserDevice.objects.all()
    serializer_class = UserDeviceSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return UserDevice.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    @action(detail=True, methods=['post'])
    def deactivate(self, request, pk=None):
        device = self.get_object()
        device.is_active = False
        device.save()
        
        # Log activity
        UserActivity.objects.create(
            user=request.user,
            activity_type='device_removed',
            device=device
        )
        
        return Response({
            'message': 'Device deactivated successfully'
        })

class UserSubscriptionViewSet(viewsets.ModelViewSet):
    queryset = UserSubscription.objects.all()
    serializer_class = UserSubscriptionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return UserSubscription.objects.filter(user=self.request.user)

    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        subscription = self.get_object()
        reason = request.data.get('reason', '')
        
        subscription.is_active = False
        subscription.cancelled_at = timezone.now()
        subscription.cancellation_reason = reason
        subscription.save()
        
        # Update user's subscription status
        user = request.user
        user.is_subscribed = False
        user.save()
        
        # Log activity
        UserActivity.objects.create(
            user=user,
            activity_type='subscription',
            details={'action': 'cancelled', 'reason': reason}
        )
        
        return Response({
            'message': 'Subscription cancelled successfully'
        })

class UserActivityViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = UserActivity.objects.all()
    serializer_class = UserActivitySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return UserActivity.objects.filter(user=self.request.user)

@api_view(['POST'])
@permission_classes([AllowAny])
def verify_otp_and_get_token(request):
    phone = request.data.get('phone')
    otp = request.data.get('otp')
    
    try:
        # Verify OTP logic here (use your existing OTP verification)
        user = User.objects.get(username=phone)
        
        # Generate tokens
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'status': 'success',
            'message': 'OTP verified successfully',
            'data': {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'user': {
                    'id': user.id,
                    'phone': user.username,
                    'is_registered': UserProfile.objects.filter(user=user).exists()
                }
            }
        })
    except User.DoesNotExist:
        return Response({
            'status': 'error',
            'message': 'User not found'
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([AllowAny])
def get_referral_info(request):
    """
    Get user's referral information including QR code and real-time referral count
    """
    try:
        # Get phone from query params
        phone = request.query_params.get('phone')
        if not phone:
            return Response({
                'status': 'error',
                'message': 'Phone number is required'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Get user profile
        try:
            user = UserProfile.objects.get(phone=phone)
        except UserProfile.DoesNotExist:
            return Response({
                'status': 'error',
                'message': 'User not found'
            }, status=status.HTTP_404_NOT_FOUND)

        # Get or create referral object
        referral, created = ReferralSystem.objects.get_or_create(
            user=user,
            defaults={'referral_code': None}  # Will be auto-generated in save()
        )
        
        # Get real-time referral count from relationships
        total_referrals = ReferralRelationship.objects.filter(
            referrer=user,
            is_converted=True
        ).count()
        
        # Get list of referred users with their details
        referred_users = ReferralRelationship.objects.filter(
            referrer=user,
            is_converted=True
        ).select_related('referee').order_by('-created_at')
        
        referred_users_data = [{
            'phone': rel.referee.phone,
            'first_name': rel.referee.first_name,
            'joined_at': rel.converted_at,
            'referral_code_used': rel.referral_code_used,
            'is_subscribed': rel.referee.is_subscribed
        } for rel in referred_users]
        
        # Check if user has been referred by someone
        is_referred = ReferralRelationship.objects.filter(referee=user).exists()
        
        return Response({
            'status': 'success',
            'referral_code': referral.referral_code,
            'qr_code_url': request.build_absolute_uri(referral.qr_code.url) if referral.qr_code else None,
            'total_referrals': total_referrals,
            'referred_users': referred_users_data,
            'is_referred': is_referred
        })
    except Exception as e:
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([AllowAny])
def verify_referral(request):
    """
    Verify if a referral code is valid
    """
    try:
        code = request.query_params.get('code')
        if not code:
            return Response({
                'status': 'error',
                'message': 'Referral code is required'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if referral code exists
        try:
            referral = ReferralSystem.objects.get(referral_code=code)
            return Response({
                'status': 'success',
                'message': 'Valid referral code',
                'referrer_id': referral.user.id
            })
        except ReferralSystem.DoesNotExist:
            return Response({
                'status': 'error',
                'message': 'Invalid referral code'
            }, status=status.HTTP_404_NOT_FOUND)

    except Exception as e:
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def create_order(request):
    try:
        # Get data from request
        amount = int(float(request.data.get('amount')))  # Convert to paise
        currency = request.data.get('currency', 'INR')
        plan_id = request.data.get('plan_id')
        
        print(f"Creating order for amount: {amount}, currency: {currency}, plan: {plan_id}")
        
        # Create Razorpay Order
        client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
        
        # Create order data
        order_data = {
            'amount': amount * 100,  # Convert to paise
            'currency': currency,
            'payment_capture': '1'  # Auto capture payment
        }
        
        print("Sending request to Razorpay:", order_data)
        
        # Create order in Razorpay
        order = client.order.create(data=order_data)
        
        print("Order created in Razorpay:", order)
        
        # Save order in database
        payment_order = PaymentOrder.objects.create(
            order_id=order['id'],
            amount=amount,
            currency=currency,
            plan_id=plan_id,
            status='created'
        )
        
        # Return order details
        return Response({
            'status': 'success',
            'key_id': settings.RAZORPAY_KEY_ID,
            'amount': order['amount'],
            'currency': order['currency'],
            'order_id': order['id']
        })
        
    except Exception as e:
        print(f"Error creating order: {str(e)}")
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def verify_payment(request):
    try:
        # Validate required fields
        required_fields = ['razorpay_payment_id', 'razorpay_order_id', 'razorpay_signature', 'phone']
        for field in required_fields:
            if not request.data.get(field):
                return Response({
                    'status': 'error',
                    'message': f'Missing required field: {field}'
                }, status=status.HTTP_400_BAD_REQUEST)

        # Get payment details from request
        payment_id = request.data.get('razorpay_payment_id')
        order_id = request.data.get('razorpay_order_id')
        signature = request.data.get('razorpay_signature')
        phone = request.data.get('phone')

        # Initialize Razorpay client
        client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

        # Verify payment signature
        params_dict = {
            'razorpay_payment_id': payment_id,
            'razorpay_order_id': order_id,
            'razorpay_signature': signature
        }

        try:
            client.utility.verify_payment_signature(params_dict)
        except Exception as e:
            print(f"Signature verification failed: {str(e)}")
            return Response({
                'status': 'error',
                'message': 'Payment signature verification failed. Please contact support.'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Get payment order
        try:
            payment_order = PaymentOrder.objects.get(order_id=order_id)
            payment_amount = Decimal(str(payment_order.amount))
        except PaymentOrder.DoesNotExist:
            return Response({
                'status': 'error',
                'message': 'Order not found. Please contact support.'
            }, status=status.HTTP_404_NOT_FOUND)

        # Get user profile
        try:
            user_profile = UserProfile.objects.get(phone=phone)
        except UserProfile.DoesNotExist:
            return Response({
                'status': 'error',
                'message': 'User not found. Please contact support.'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Create payment transaction
        try:
            with transaction.atomic():
                # Create payment transaction record
                payment_transaction = PaymentTransaction.objects.create(
                    order=payment_order,
                    payment_id=payment_id,
                    signature=signature,
                    status='success'
                )

                # Update order status
                payment_order.status = 'completed'
                payment_order.save()

                # Process referral bonus if applicable
                referral_relationship = ReferralRelationship.objects.filter(
                    referee=user_profile,
                    is_converted=True
                ).first()

                if referral_relationship:
                    referrer = referral_relationship.referrer
                    
                    # Get referral bonus levels
                    bonus_levels = ReferralBonus.objects.filter(is_active=True).order_by('level')
                    
                    # Get all referrers in the chain up to 5 levels
                    referrers = []
                    current_user = user_profile
                    visited = set()  # To prevent infinite loops
                    
                    # Find all referrers up to 5 levels
                    while len(referrers) < 5 and current_user and current_user.id not in visited:
                        visited.add(current_user.id)
                        rel = ReferralRelationship.objects.filter(
                            referee=current_user,
                            is_converted=True
                        ).first()
                        
                        if rel:
                            referrers.append(rel.referrer)
                            current_user = rel.referrer
                        else:
                            break
                    
                    # Process bonus for each level based on available referrers
                    for idx, bonus_level in enumerate(bonus_levels):
                        if idx < len(referrers):  # Only process if we have a referrer for this level
                            referrer = referrers[idx]
                            
                            # Calculate bonus amount with proper decimal handling
                            bonus_percentage = Decimal(str(bonus_level.amount))
                            bonus_amount = (payment_amount * bonus_percentage) / Decimal('100.0')
                            
                            print(f"Processing Level {bonus_level.level} bonus: {bonus_amount} ({bonus_percentage}% of {payment_amount})")
                            
                            # Create referral transaction
                            referral_transaction = ReferralTransaction.objects.create(
                                referrer=referrer,
                                referred_user=user_profile,
                                amount=bonus_amount,
                                level=bonus_level.level,
                                transaction_type='commission',
                                status='completed',
                                processed_at=timezone.now(),
                                description=f'Level {bonus_level.level} commission for payment of ₹{payment_amount}'
                            )
                            
                            # Get or create referrer's wallet
                            wallet, created = Wallet.objects.get_or_create(
                                user=referrer,
                                defaults={'balance': Decimal('0.00')}
                            )
                            
                            # Create wallet transaction
                            wallet_transaction = WalletTransaction.objects.create(
                                wallet=wallet,
                                amount=bonus_amount,
                                transaction_type='REFERRAL_BONUS',
                                status='COMPLETED',
                                reference_id=f'REF-{payment_transaction.id}-{bonus_level.level}',
                                description=f'Referral bonus for payment by {user_profile.phone}'
                            )
                            
                            # Update wallet balance
                            wallet.balance = Decimal(str(wallet.balance)) + bonus_amount
                            wallet.save()
                            
                            print(f"Wallet updated for Level {bonus_level.level}. New balance: {wallet.balance}")
                        else:
                            break  # No more referrers in chain

                # Create subscription for user
                start_date = timezone.now()
                end_date = start_date + timedelta(days=int(payment_order.plan_id.split('_')[-1]))
                
                UserSubscription.objects.create(
                    user=user_profile,
                    plan_name=payment_order.plan_id,
                    plan_duration=int(payment_order.plan_id.split('_')[-1]),
                    amount=payment_amount,
                    payment_id=payment_id,
                    payment_status='success',
                    start_date=start_date,
                    end_date=end_date,
                    is_active=True
                )

                # Update user subscription status
                user_profile.is_subscribed = True
                user_profile.subscription_start_date = start_date
                user_profile.subscription_end_date = end_date
                user_profile.subscription_type = payment_order.plan_id
                user_profile.save()

                return Response({
                    'status': 'success',
                    'message': 'Payment verified and subscription activated successfully.'
                })

        except Exception as e:
            print(f"Error processing payment: {str(e)}")
            return Response({
                'status': 'error',
                'message': 'Payment failed. Please contact support.'
            }, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        print(f"Payment verification failed: {str(e)}")
        return Response({
            'status': 'error',
            'message': 'Payment failed. Please contact support.'
        }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def referral_dashboard(request):
    """
    Get referral dashboard data for the authenticated user
    """
    try:
        # Get user's referral info
        referral = ReferralSystem.objects.get(user=request.user)
        
        # Get total earnings
        total_earnings = ReferralTransaction.objects.filter(
            referrer=request.user,
            status='completed'
        ).aggregate(total=Sum('amount'))['total'] or 0
        
        # Get bonus levels
        bonus_levels = ReferralBonus.objects.filter(is_active=True).order_by('level')
        
        # Get recent transactions
        recent_transactions = ReferralTransaction.objects.filter(
            referrer=request.user,
            status='completed'
        ).order_by('-created_at')[:10]
        
        return Response({
            'referral_code': referral.referral_code,
            'qr_code_url': referral.qr_code.url if referral.qr_code else None,
            'total_earnings': float(total_earnings),
            'total_referrals': referral.total_referrals,
            'bonus_levels': [
                {
                    'level': level.level,
                    'amount': float(level.amount),
                    'description': level.description
                }
                for level in bonus_levels
            ],
            'recent_transactions': [
                {
                    'id': tx.id,
                    'amount': float(tx.amount),
                    'transaction_type': tx.transaction_type,
                    'level': tx.level,
                    'created_at': tx.created_at
                }
                for tx in recent_transactions
            ]
        })
    except ReferralSystem.DoesNotExist:
        return Response({
            'error': 'Referral information not found'
        }, status=404)
    except Exception as e:
        return Response({
            'error': str(e)
        }, status=500)

class WalletViewSet(viewsets.ModelViewSet):
    serializer_class = WalletSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        phone = self.request.query_params.get('phone')
        if not phone:
            return Wallet.objects.none()
        try:
            user = UserProfile.objects.get(phone=phone)
            return Wallet.objects.filter(user=user)
        except UserProfile.DoesNotExist:
            return Wallet.objects.none()

    def get_object(self):
        phone = self.request.query_params.get('phone')
        if not phone:
            return None
        try:
            user = UserProfile.objects.get(phone=phone)
            wallet, created = Wallet.objects.get_or_create(user=user)
            return wallet
        except UserProfile.DoesNotExist:
            return None

    @action(detail=False, methods=['get'])
    def transactions(self, request):
        wallet = self.get_object()
        if not wallet:
            return Response({'error': 'Wallet not found'}, status=status.HTTP_404_NOT_FOUND)
            
        transactions = WalletTransaction.objects.filter(wallet=wallet).order_by('-created_at')
        page = self.paginate_queryset(transactions)
        if page is not None:
            serializer = WalletTransactionSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = WalletTransactionSerializer(transactions, many=True)
        return Response(serializer.data)

class BankAccountViewSet(viewsets.ModelViewSet):
    serializer_class = BankAccountSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        phone = self.request.query_params.get('phone')
        if not phone:
            return BankAccount.objects.none()
        try:
            user = UserProfile.objects.get(phone=phone)
            return BankAccount.objects.filter(user=user)
        except UserProfile.DoesNotExist:
            return BankAccount.objects.none()

    def perform_create(self, serializer):
        phone = self.request.data.get('phone')
        if not phone:
            raise serializers.ValidationError({'phone': 'Phone number is required'})
        try:
            user = UserProfile.objects.get(phone=phone)
            # If this is the first bank account, make it primary
            if not BankAccount.objects.filter(user=user).exists():
                serializer.save(user=user, is_primary=True)
            else:
                serializer.save(user=user)
        except UserProfile.DoesNotExist:
            raise serializers.ValidationError({'phone': 'User not found'})

    @action(detail=True, methods=['post'])
    def set_primary(self, request, pk=None):
        phone = request.data.get('phone')
        if not phone:
            return Response({'error': 'Phone number is required'}, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            user = UserProfile.objects.get(phone=phone)
            bank_account = self.get_object()
            
            if bank_account.user != user:
                return Response({'error': 'Bank account does not belong to user'}, status=status.HTTP_403_FORBIDDEN)
                
            with transaction.atomic():
                BankAccount.objects.filter(user=user).update(is_primary=False)
                bank_account.is_primary = True
                bank_account.save()
            return Response({'status': 'Bank account set as primary'})
        except UserProfile.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

class WalletTransactionViewSet(viewsets.ModelViewSet):
    serializer_class = WalletTransactionSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        phone = self.request.query_params.get('phone')
        if not phone:
            phone = self.request.data.get('phone')  # Also check in request data for PUT/POST
        if not phone:
            return WalletTransaction.objects.none()
        try:
            user = UserProfile.objects.get(phone=phone)
            return WalletTransaction.objects.filter(wallet__user=user)
        except UserProfile.DoesNotExist:
            return WalletTransaction.objects.none()

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def referral_earnings(request):
    try:
        user_profile = UserProfile.objects.get(phone=request.user.phone)
        
        # Get all referral transactions for this user
        referral_transactions = ReferralTransaction.objects.filter(
            referrer=user_profile,
            status='completed'
        ).order_by('-created_at')
        
        # Calculate total earnings
        total_earnings = referral_transactions.aggregate(
            total=Sum('amount')
        )['total'] or 0
        
        # Get wallet balance
        wallet = Wallet.objects.filter(user=user_profile).first()
        current_balance = wallet.balance if wallet else 0
        
        # Get referral bonus levels
        bonus_levels = ReferralBonus.objects.filter(
            is_active=True
        ).order_by('level')
        
        # Get recent transactions
        recent_transactions = []
        for transaction in referral_transactions[:10]:  # Last 10 transactions
            recent_transactions.append({
                'id': transaction.id,
                'amount': str(transaction.amount),
                'level': transaction.level,
                'referred_user': transaction.referred_user.phone,
                'transaction_type': transaction.transaction_type,
                'processed_at': transaction.processed_at.strftime('%Y-%m-%d %H:%M:%S'),
                'description': transaction.description
            })
        
        # Get bonus level details
        bonus_level_details = []
        for level in bonus_levels:
            bonus_level_details.append({
                'level': level.level,
                'percentage': str(level.amount),
                'description': level.description
            })
        
        return Response({
            'status': 'success',
            'data': {
                'total_earnings': str(total_earnings),
                'current_balance': str(current_balance),
                'bonus_levels': bonus_level_details,
                'recent_transactions': recent_transactions
            }
        })
        
    except UserProfile.DoesNotExist:
        return Response({
            'status': 'error',
            'message': 'User profile not found'
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([AllowAny])
def get_withdrawal_limits(request):
    """Get withdrawal limits and remaining withdrawals for today"""
    try:
        phone = request.query_params.get('phone')
        if not phone:
            return Response({'error': 'Phone number is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = UserProfile.objects.get(phone=phone)
            wallet = Wallet.objects.get(user=user)
            
            # Get withdrawal settings
            settings = WithdrawalSettings.get_settings()
            
            # Get remaining withdrawals for today
            daily_withdrawals = WalletTransaction.get_daily_withdrawal_count(wallet)
            remaining_withdrawals = settings.max_daily_withdrawals - daily_withdrawals
            
            return Response({
                'min_amount': float(settings.min_withdrawal_amount),
                'max_amount': float(settings.max_withdrawal_amount),
                'daily_limit': settings.max_daily_withdrawals,
                'remaining_today': remaining_withdrawals
            })
            
        except UserProfile.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except Wallet.DoesNotExist:
            return Response({'error': 'Wallet not found'}, status=status.HTTP_404_NOT_FOUND)
            
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([AllowAny])
def request_withdrawal(request):
    """Handle withdrawal requests"""
    phone = request.data.get('phone')
    if not phone:
        return Response({'error': 'Phone number is required'}, status=status.HTTP_400_BAD_REQUEST)
        
    try:
        # Get user and wallet
        try:
            user = UserProfile.objects.get(phone=phone)
            wallet = Wallet.objects.get(user=user)
        except UserProfile.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except Wallet.DoesNotExist:
            # Create wallet if it doesn't exist
            wallet = Wallet.objects.create(user=user, balance=Decimal('0.00'))
            return Response({'error': 'Insufficient wallet balance'}, status=status.HTTP_400_BAD_REQUEST)

        amount = request.data.get('amount')
        bank_account_id = request.data.get('bank_account')

        # Validate amount
        try:
            amount = Decimal(str(amount))
            if amount <= 0:
                return Response({'error': 'Amount must be greater than 0'}, status=status.HTTP_400_BAD_REQUEST)
        except (ValueError, TypeError, InvalidOperation):
            return Response({'error': 'Invalid amount'}, status=status.HTTP_400_BAD_REQUEST)

        # Get withdrawal settings
        settings = WithdrawalSettings.get_settings()
        
        # Validate minimum amount
        if amount < settings.min_withdrawal_amount:
            return Response({
                'error': f'Minimum withdrawal amount is ₹{settings.min_withdrawal_amount}',
                'min_amount': float(settings.min_withdrawal_amount)
            }, status=status.HTTP_400_BAD_REQUEST)
            
        # Validate maximum amount
        if amount > settings.max_withdrawal_amount:
            return Response({
                'error': f'Maximum withdrawal amount is ₹{settings.max_withdrawal_amount}',
                'max_amount': float(settings.max_withdrawal_amount)
            }, status=status.HTTP_400_BAD_REQUEST)
            
        # Check daily withdrawal limit
        daily_withdrawals = WalletTransaction.get_daily_withdrawal_count(wallet)
        if daily_withdrawals >= settings.max_daily_withdrawals:
            return Response({
                'error': f'Daily withdrawal limit of {settings.max_daily_withdrawals} reached',
                'daily_limit': settings.max_daily_withdrawals,
                'remaining_today': 0
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate wallet balance
        if amount > wallet.balance:
            return Response({
                'error': 'Insufficient wallet balance',
                'current_balance': float(wallet.balance)
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate bank account
        try:
            bank_account = BankAccount.objects.get(id=bank_account_id, user=user)
            if not bank_account.is_verified:
                return Response({
                    'error': 'Bank account is not verified',
                    'bank_account_id': bank_account_id
                }, status=status.HTTP_400_BAD_REQUEST)
        except BankAccount.DoesNotExist:
            return Response({
                'error': 'Invalid bank account',
                'bank_account_id': bank_account_id
            }, status=status.HTTP_400_BAD_REQUEST)
            
        # Use select_for_update to prevent race conditions
        with transaction.atomic():
            wallet = Wallet.objects.select_for_update().get(id=wallet.id)
            
            # Recheck balance after lock
            if amount > wallet.balance:
                return Response({
                    'error': 'Insufficient wallet balance',
                    'current_balance': float(wallet.balance)
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Create withdrawal transaction
            withdrawal = WalletTransaction.objects.create(
                wallet=wallet,
                amount=amount,
                transaction_type='WITHDRAWAL',
                status='PENDING',
                reference_id=f'WD-{uuid.uuid4().hex[:8].upper()}',
                bank_account=bank_account,
                description=f'Withdrawal request to {bank_account.bank_name} account ending with {bank_account.account_number[-4:]}'
            )
            
            # Update wallet balance
            wallet.balance -= amount
            wallet.save()

            # Create activity log
            UserActivity.objects.create(
                user=user,
                activity_type='withdrawal',
                details={
                    'amount': str(amount),
                    'bank_account': bank_account.account_number[-4:],
                    'reference_id': withdrawal.reference_id,
                    'status': 'pending'
                }
            )

            return Response({
                'status': 'success',
                'message': 'Withdrawal request created successfully',
                'transaction': WalletTransactionSerializer(withdrawal).data
            }, status=status.HTTP_201_CREATED)

    except Exception as e:
        import traceback
        print(f"Withdrawal Error for {phone}: {str(e)}")
        print(traceback.format_exc())
        return Response({
            'error': 'An unexpected error occurred. Please try again later.',
            'detail': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([AllowAny])
def check_withdrawal_status(request):
    """Check the status of a withdrawal transaction"""
    phone = request.query_params.get('phone')
    reference_id = request.query_params.get('reference_id')
    
    if not phone or not reference_id:
        return Response({
            'error': 'Both phone and reference_id are required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = UserProfile.objects.get(phone=phone)
        transaction = WalletTransaction.objects.filter(
            wallet__user=user,
            reference_id=reference_id,
            transaction_type='WITHDRAWAL'
        ).select_related('wallet', 'bank_account').first()
        
        if not transaction:
            return Response({
                'error': 'Transaction not found'
            }, status=status.HTTP_404_NOT_FOUND)
            
        response_data = {
            'status': transaction.status,
            'amount': float(transaction.amount),
            'reference_id': transaction.reference_id,
            'created_at': transaction.created_at,
            'updated_at': transaction.updated_at,
            'bank_account': {
                'bank_name': transaction.bank_account.bank_name,
                'account_number': f"XXXX{transaction.bank_account.account_number[-4:]}",
            }
        }
        
        # Add additional details based on status
        if transaction.status == 'FAILED':
            # Get the failure activity log
            failure_log = UserActivity.objects.filter(
                user=user,
                activity_type='withdrawal_failed',
                details__reference_id=reference_id
            ).first()
            
            if failure_log:
                response_data['failure_reason'] = failure_log.details.get('reason') or failure_log.details.get('error')
        
        return Response(response_data)
        
    except UserProfile.DoesNotExist:
        return Response({
            'error': 'User not found'
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({
            'error': 'An error occurred while checking withdrawal status',
            'detail': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([AllowAny])
def get_referral_bonus_levels(request):
    """Get referral bonus levels"""
    try:
        phone = request.query_params.get('phone')
        if not phone:
            return Response({'error': 'Phone number is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = UserProfile.objects.get(phone=phone)
            bonus_levels = ReferralBonus.objects.filter(is_active=True).order_by('level')
            
            response_data = []
            for level in bonus_levels:
                response_data.append({
                    'level': level.level,
                    'amount': float(level.amount),
                    'description': level.description
                })
            
            return Response({
                'status': 'success',
                'bonus_levels': response_data
            })
            
        except UserProfile.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
            
    except Exception as e:
        return Response({
            'error': 'An error occurred while fetching bonus levels',
            'detail': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([AllowAny])
def get_wallet(request):
    """Get user's wallet details"""
    try:
        phone = request.query_params.get('phone')
        if not phone:
            return Response({'error': 'Phone number is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = UserProfile.objects.get(phone=phone)
            wallet, created = Wallet.objects.get_or_create(
                user=user,
                defaults={'balance': Decimal('0.00')}
            )
            
            # Get recent transactions
            recent_transactions = WalletTransaction.objects.filter(
                wallet=wallet
            ).order_by('-created_at')[:10]
            
            response_data = {
                'id': wallet.id,
                'balance': float(wallet.balance),
                'created_at': wallet.created_at,
                'updated_at': wallet.updated_at,
                'recent_transactions': [
                    {
                        'id': tx.id,
                        'amount': float(tx.amount),
                        'transaction_type': tx.transaction_type,
                        'status': tx.status,
                        'reference_id': tx.reference_id,
                        'created_at': tx.created_at,
                        'description': tx.description
                    } for tx in recent_transactions
                ]
            }
            
            return Response(response_data)
            
        except UserProfile.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
            
    except Exception as e:
        return Response({
            'error': 'An error occurred while fetching wallet details',
            'detail': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
