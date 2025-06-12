import os
import requests
from django.conf import settings

class OTPService:
    def __init__(self):
        self.auth_key = settings.MSG91_AUTH_KEY
        self.template_id = settings.MSG91_TEMPLATE_ID
        self.sender_id = settings.MSG91_SENDER_ID
        self.base_url = "https://api.msg91.com/api/v5"

    def clean_phone_number(self, phone_number):
        # Remove any non-digit characters
        phone_number = ''.join(filter(str.isdigit, phone_number))
        # Remove country code if present
        if phone_number.startswith('91'):
            phone_number = phone_number[2:]
        return phone_number

    def format_phone_for_msg91(self, phone_number):
        # Clean the number first
        phone_number = self.clean_phone_number(phone_number)
        # Add country code for MSG91
        return f"91{phone_number}"

    def send_otp(self, phone_number, otp):
        try:
            # Format phone number for MSG91
            phone_number = self.format_phone_for_msg91(phone_number)
            
            # Prepare the request
            url = f"{self.base_url}/flow/"
            headers = {
                "authkey": self.auth_key,
                "Content-Type": "application/json"
            }
            payload = {
                "template_id": self.template_id,
                "sender": self.sender_id,
                "short_url": "0",
                "mobiles": phone_number,
                "var": str(otp)
            }
            
            # Send OTP request
            response = requests.post(url, headers=headers, json=payload)
            response_data = response.json()
            
            if response.status_code == 200 and response_data.get('type') == 'success':
                return True, "OTP sent successfully"
            else:
                return False, f"Failed to send OTP: {response_data.get('message', 'Unknown error')}"
                
        except Exception as e:
            return False, f"Error sending OTP: {str(e)}"

    def verify_otp(self, phone_number, otp):
        try:
            # Format phone number for MSG91
            phone_number = self.format_phone_for_msg91(phone_number)
            
            # Prepare the request
            url = f"{self.base_url}/otp/verify"
            headers = {
                "authkey": self.auth_key,
                "Content-Type": "application/json"
            }
            payload = {
                "mobile": phone_number,
                "otp": otp
            }
            
            # Send verification request
            response = requests.post(url, headers=headers, json=payload)
            response_data = response.json()
            
            if response.status_code == 200 and response_data.get('type') == 'success':
                return True, "OTP verified successfully"
            else:
                return False, f"Invalid OTP: {response_data.get('message', 'Verification failed')}"
                
        except Exception as e:
            return False, f"Error verifying OTP: {str(e)}"

    def send_subscription_success(self, phone_number, plan_name, end_date):
        try:
            # Format phone number for MSG91
            phone_number = self.format_phone_for_msg91(phone_number)
            
            # Prepare the request
            url = f"{self.base_url}/flow/"
            headers = {
                "authkey": self.auth_key,
                "Content-Type": "application/json"
            }
            payload = {
                "template_id": settings.MSG91_SUBSCRIPTION_SUCCESS_TEMPLATE_ID,
                "sender": self.sender_id,
                "short_url": "0",
                "mobiles": phone_number
            }
            
            # Send SMS request
            response = requests.post(url, headers=headers, json=payload)
            response_data = response.json()
            
            if response.status_code == 200 and response_data.get('type') == 'success':
                return True, "Subscription success SMS sent"
            else:
                return False, f"Failed to send SMS: {response_data.get('message', 'Unknown error')}"
                
        except Exception as e:
            return False, f"Error sending SMS: {str(e)}" 