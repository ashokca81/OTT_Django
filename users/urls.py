from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views
from .views import (
    WalletViewSet,
    BankAccountViewSet,
    WalletTransactionViewSet,
    UserViewSet,
    UserDeviceViewSet,
    UserSubscriptionViewSet,
    UserActivityViewSet,
    verify_otp_and_get_token,
    get_referral_info,
    verify_referral,
    create_order,
    verify_payment,
    referral_dashboard,
    referral_earnings,
    get_withdrawal_limits,
    request_withdrawal,
    check_withdrawal_status,
    get_referral_bonus_levels,
    get_wallet
)

router = DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'devices', UserDeviceViewSet)
router.register(r'subscriptions', UserSubscriptionViewSet)
router.register(r'activities', UserActivityViewSet)
router.register(r'wallets', WalletViewSet, basename='wallet')
router.register(r'bank-accounts', BankAccountViewSet, basename='bank-account')
router.register(r'wallet-transactions', WalletTransactionViewSet, basename='wallet-transaction')

urlpatterns = [
    # Include router URLs first
    path('', include(router.urls)),
    
    # Custom endpoints
    path('request-otp/', UserViewSet.as_view({'post': 'request_otp'}), name='request-otp'),
    path('verify-otp/', UserViewSet.as_view({'post': 'verify_otp'}), name='verify-otp'),
    path('login/', UserViewSet.as_view({'post': 'login'}), name='login'),
    path('profile/', UserViewSet.as_view({'get': 'get_profile'}), name='get-profile'),
    path('update-profile/', UserViewSet.as_view({'post': 'update_profile'}), name='update-profile'),
    path('complete-registration/', UserViewSet.as_view({'post': 'complete_registration'}), name='complete-registration'),
    path('devices-info/', UserViewSet.as_view({'get': 'get_devices_info'}), name='devices-info'),
    path('add-device/', UserViewSet.as_view({'post': 'add_device'}), name='add-device'),
    path('deactivate-device/', UserViewSet.as_view({'post': 'deactivate_device'}), name='deactivate-device'),
    path('verify-otp-token/', verify_otp_and_get_token, name='verify-otp-token'),
    path('referral-info/', get_referral_info, name='referral-info'),
    path('verify-referral/', verify_referral, name='verify-referral'),
    path('create-order/', create_order, name='create-order'),
    path('verify-payment/', verify_payment, name='verify-payment'),
    path('referral-dashboard/', referral_dashboard, name='referral-dashboard'),
    path('referral-earnings/', referral_earnings, name='referral-earnings'),
    path('withdrawal-limits/', get_withdrawal_limits, name='withdrawal-limits'),
    path('request-withdrawal/', request_withdrawal, name='request-withdrawal'),
    path('check-withdrawal-status/', check_withdrawal_status, name='check-withdrawal-status'),
    path('referral-bonus-levels/', get_referral_bonus_levels, name='referral-bonus-levels'),
    path('wallet/', get_wallet, name='get-wallet'),
]
