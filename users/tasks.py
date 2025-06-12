from celery import shared_task
from django.utils import timezone
from django.db import transaction
from .models import WalletTransaction, UserActivity
import logging

logger = logging.getLogger(__name__)

@shared_task
def process_pending_withdrawals():
    """
    Process pending withdrawal transactions
    This task should be scheduled to run periodically
    """
    try:
        # Get all pending withdrawals
        pending_withdrawals = WalletTransaction.objects.filter(
            transaction_type='WITHDRAWAL',
            status='PENDING'
        ).select_related('wallet', 'bank_account')

        for withdrawal in pending_withdrawals:
            try:
                with transaction.atomic():
                    # Lock the withdrawal record
                    withdrawal = WalletTransaction.objects.select_for_update().get(id=withdrawal.id)
                    
                    if withdrawal.status != 'PENDING':
                        continue

                    # Here you would integrate with your payment gateway
                    # For example, using Razorpay payout API
                    try:
                        # Implement your payout logic here
                        # payout_response = razorpay_client.payout.create({
                        #     'account_number': withdrawal.bank_account.account_number,
                        #     'amount': int(withdrawal.amount * 100),  # Convert to paise
                        #     'currency': 'INR',
                        #     'mode': 'NEFT',
                        #     'purpose': 'payout',
                        #     'reference_id': withdrawal.reference_id,
                        # })
                        
                        # For now, we'll simulate successful payout
                        payout_successful = True
                        
                        if payout_successful:
                            withdrawal.status = 'COMPLETED'
                            withdrawal.save()
                            
                            # Log the activity
                            UserActivity.objects.create(
                                user=withdrawal.wallet.user,
                                activity_type='withdrawal_completed',
                                details={
                                    'amount': str(withdrawal.amount),
                                    'bank_account': withdrawal.bank_account.account_number[-4:],
                                    'reference_id': withdrawal.reference_id
                                }
                            )
                        else:
                            # If payout fails, revert the transaction
                            withdrawal.status = 'FAILED'
                            withdrawal.save()
                            
                            # Refund the amount to wallet
                            wallet = withdrawal.wallet
                            wallet.balance += withdrawal.amount
                            wallet.save()
                            
                            # Log the failure
                            UserActivity.objects.create(
                                user=withdrawal.wallet.user,
                                activity_type='withdrawal_failed',
                                details={
                                    'amount': str(withdrawal.amount),
                                    'bank_account': withdrawal.bank_account.account_number[-4:],
                                    'reference_id': withdrawal.reference_id,
                                    'reason': 'Payout failed'
                                }
                            )
                            
                    except Exception as e:
                        logger.error(f"Error processing withdrawal {withdrawal.reference_id}: {str(e)}")
                        withdrawal.status = 'FAILED'
                        withdrawal.save()
                        
                        # Refund the amount to wallet
                        wallet = withdrawal.wallet
                        wallet.balance += withdrawal.amount
                        wallet.save()
                        
                        # Log the error
                        UserActivity.objects.create(
                            user=withdrawal.wallet.user,
                            activity_type='withdrawal_failed',
                            details={
                                'amount': str(withdrawal.amount),
                                'bank_account': withdrawal.bank_account.account_number[-4:],
                                'reference_id': withdrawal.reference_id,
                                'error': str(e)
                            }
                        )
                        
            except Exception as e:
                logger.error(f"Error processing withdrawal {withdrawal.id}: {str(e)}")
                continue

    except Exception as e:
        logger.error(f"Error in process_pending_withdrawals task: {str(e)}")
        raise 