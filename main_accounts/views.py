from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
from .models import UserProfile, LoginHistory, BugReport, BugReportReply, Category, LiveStream, State, District, Constituency, Mandal, Village, RegionalVideo, Video, VideoPrice, UserVideo, Cast, VideoCast
from django.contrib.auth.models import User
from django.views.decorators.http import require_http_methods
from django.db.models import Q, Max, Count, OuterRef, Subquery, Sum, F
import json
import xlsxwriter
from io import BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph
from django.utils import timezone
from django.core.paginator import Paginator
from rest_framework import viewsets, permissions
from .utils import convert_to_hls, upload_hls_to_s3, process_video_upload, process_promo_video
from .serializers import LiveStreamSerializer, CategorySerializer, StateSerializer, DetailedStateSerializer, DistrictSerializer, DetailedDistrictSerializer, ConstituencySerializer, DetailedConstituencySerializer, MandalSerializer, DetailedMandalSerializer, VillageSerializer, DetailedVillageSerializer, RegionalVideoSerializer, VideoSerializer, VideoPriceSerializer, UserVideoSerializer
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.permissions import AllowAny
from django.db import transaction
import logging
from decimal import Decimal
from users.models import ReferralBonus
import decimal
from django.views.decorators.http import require_POST
from users.models import WalletTransaction, WithdrawalSettings
from datetime import datetime, timedelta
from django.utils.text import slugify
import os
import tempfile
from django.core.files.storage import default_storage
from .utils import convert_to_hls, upload_hls_to_s3
from django.core.files import File
from concurrent.futures import ThreadPoolExecutor
from django.core.paginator import PageNotAnInteger, EmptyPage

logger = logging.getLogger('main_accounts.views')

def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
        
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        try:
            # First find the user by email
            user = User.objects.get(email=email)
            # Then authenticate with username and password
            auth_user = authenticate(request, username=user.username, password=password)
            
            if auth_user is not None:
                login(request, auth_user)
                # Set user as online
                user_profile = UserProfile.objects.get(user=auth_user)
                user_profile.is_online = True
                user_profile.save()
                
                # Check if a login record already exists for this session
                session_key = request.session.session_key
                if not LoginHistory.objects.filter(
                    user=auth_user,
                    timestamp__gte=timezone.now() - timezone.timedelta(minutes=1)
                ).exists():
                    # Record login history only if no recent record exists
                    LoginHistory.objects.create(
                        user=auth_user,
                        ip_address=request.META.get('REMOTE_ADDR'),
                        user_agent=request.META.get('HTTP_USER_AGENT', '')
                    )
                
                return JsonResponse({'status': 'success'})
            else:
                return JsonResponse({'status': 'error', 'message': 'Invalid password'}, status=400)
        except User.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'No account found with this email'}, status=400)
    
    return render(request, 'login/login.html')

@login_required(login_url='login')
def dashboard_view(request):
    user_profile = UserProfile.objects.get(user=request.user)
    context = {
        'user_profile': user_profile,
        'role': user_profile.role.get_name_display()
    }
    return render(request, 'dashboard/index.html', context)

@login_required(login_url='login')
def profile_view(request):
    user_profile = UserProfile.objects.get(user=request.user)
    
    # Get the last 5 login records
    login_history = LoginHistory.objects.filter(user=request.user).order_by('-timestamp')[:5]
    
    # If user is a manager, get list of editors
    editors = None
    if user_profile.role.name == 'manager':
        editors = UserProfile.objects.filter(role__name='editor').select_related('user', 'role')
    
    context = {
        'user_profile': user_profile,
        'role': user_profile.role.get_name_display(),
        'is_manager': user_profile.role.name == 'manager',
        'editors': editors,
        'login_history': login_history
    }
    return render(request, 'profile/profile.html', context)

@login_required(login_url='login')
def settings_view(request):
    user_profile = UserProfile.objects.get(user=request.user)
    
    if request.method == 'POST':
        try:
            # Get form data
            first_name = request.POST.get('first_name')
            last_name = request.POST.get('last_name')
            email = request.POST.get('email')
            phone = request.POST.get('phone_number')

            # Update User model
            request.user.first_name = first_name
            request.user.last_name = last_name
            request.user.email = email
            request.user.save()

            # Update UserProfile model
            user_profile.phone = phone
            user_profile.save()

            messages.success(request, 'Settings updated successfully!')
            return redirect('settings')
            
        except Exception as e:
            messages.error(request, f'Error updating settings: {str(e)}')
            return redirect('settings')

    context = {
        'user_profile': user_profile,
        'role': user_profile.role.get_name_display()
    }
    return render(request, 'settings/settings.html', context)

def logout_view(request):
    if request.user.is_authenticated:
        # Set user as offline
        user_profile = UserProfile.objects.get(user=request.user)
        user_profile.is_online = False
        user_profile.save()
    logout(request)
    messages.info(request, 'You have been logged out.')
    return redirect('login')

@login_required
def create_manager(request):
    # Get the current user's profile
    current_user_profile = UserProfile.objects.get(user=request.user)
    
    # Only superusers and managers can access this page
    if not request.user.is_superuser and current_user_profile.role.name != 'manager':
        messages.error(request, 'You do not have permission to create users')
        return redirect('dashboard')
    
    if request.method == 'POST':
        try:
            # Get form data
            first_name = request.POST.get('first_name')
            last_name = request.POST.get('last_name')
            email = request.POST.get('email')
            phone = request.POST.get('phone')
            username = request.POST.get('username')
            password = request.POST.get('password')
            role_name = request.POST.get('role')

            # Validate required fields
            if not all([first_name, last_name, email, username, password, role_name]):
                messages.error(request, 'All fields are required')
                return redirect('create_manager')

            # Check if username or email already exists
            if User.objects.filter(username=username).exists():
                messages.error(request, 'Username already exists')
                return redirect('create_manager')
            
            if User.objects.filter(email=email).exists():
                messages.error(request, 'Email already exists')
                return redirect('create_manager')

            # If user is manager (not superuser), they can only create editors
            if not request.user.is_superuser and role_name != 'editor':
                messages.error(request, 'You can only create editor accounts')
                return redirect('create_manager')

            # Create user
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name
            )

            # Get the role object
            from .models import UserRole
            role = UserRole.objects.get(name=role_name)

            # Create user profile with the role object
            profile = UserProfile.objects.create(
                user=user,
                role=role,
                phone=phone
            )

            messages.success(request, f'{role_name.title()} created successfully!')
            return redirect('manage_users')
            
        except Exception as e:
            messages.error(request, f'Error creating user: {str(e)}')
            return redirect('create_manager')

    context = {
        'user_profile': current_user_profile,
        'is_superuser': request.user.is_superuser,
        'is_manager': current_user_profile.role.name == 'manager',
        'page_title': 'Add Editor' if current_user_profile.role.name == 'manager' else 'Add User'
    }
    return render(request, 'managers/create.html', context)

@login_required
def manage_users(request):
    # Get the current user's profile
    current_user_profile = UserProfile.objects.get(user=request.user)
    
    # If superuser, show all users. If manager, show only editors
    if request.user.is_superuser:
        users = UserProfile.objects.filter(role__name__in=['editor', 'manager']).select_related('user', 'role')
    else:
        # Managers can only see editors
        users = UserProfile.objects.filter(role__name='editor').select_related('user', 'role')
    
    context = {
        'user_profile': current_user_profile,
        'users': users,
        'is_superuser': request.user.is_superuser,
        'is_manager': current_user_profile.role.name == 'manager'
    }
    return render(request, 'managers/manage_users.html', context)

@login_required
@require_http_methods(["GET", "PUT"])
def user_api(request, user_id):
    if request.method == "GET":
        try:
            user = get_object_or_404(User, id=user_id)
            user_profile = get_object_or_404(UserProfile, user=user)
            
            data = {
                'id': user.id,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email': user.email,
                'phone': user_profile.phone,
                'role': user_profile.role.name,
            }
            return JsonResponse(data)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    
    elif request.method == "PUT":
        try:
            user = get_object_or_404(User, id=user_id)
            user_profile = get_object_or_404(UserProfile, user=user)
            
            # Get current user's profile to check permissions
            current_user_profile = UserProfile.objects.get(user=request.user)
            
            # Debug information
            print(f"Current user: {request.user.username}")
            print(f"Current user role: {current_user_profile.role.name}")
            print(f"Is superuser: {request.user.is_superuser}")
            
            # Check if current user has permission (must be a manager or superuser)
            if not request.user.is_superuser and current_user_profile.role.name != 'manager':
                return JsonResponse({
                    'success': False,
                    'message': f'Permission denied. Your role ({current_user_profile.role.name}) does not allow updating user details. You need to be a manager.'
                }, status=403)
            
            data = json.loads(request.body)
            
            # Update User model
            if 'first_name' in data:
                user.first_name = data['first_name']
            if 'last_name' in data:
                user.last_name = data['last_name']
            if 'email' in data:
                user.email = data['email']
            
            # Update password if provided and not empty
            if data.get('password'):
                user.set_password(data['password'])
            
            user.save()
            
            # Update UserProfile model
            if 'phone' in data:
                user_profile.phone = data['phone']
            if 'role' in data:
                from .models import UserRole
                role = UserRole.objects.get(name=data['role'])
                user_profile.role = role
            user_profile.save()
            
            return JsonResponse({
                'success': True,
                'message': 'User updated successfully'
            })
            
        except Exception as e:
            print(f"Error updating user: {str(e)}")  # Debug information
            return JsonResponse({
                'success': False,
                'message': str(e)
            }, status=400)

@login_required
@require_http_methods(["POST"])
def toggle_user_status(request, user_id):
    try:
        # Import required models
        from users.models import UserProfile as AppUserProfile, ReferralRelationship
        import logging
        
        logger = logging.getLogger(__name__)
        logger.info(f"Attempting to toggle status for user {user_id}")
        
        # Get the user
        user = get_object_or_404(AppUserProfile, id=user_id)
        
        # Toggle status
        new_status = 'inactive' if user.status == 'active' else 'active'
        user.status = new_status
        user.save()
        
        # Get updated referral count
        referral_count = ReferralRelationship.objects.filter(
            referrer=user,
            is_converted=True
        ).count()
        
        logger.info(f"Successfully toggled status for user {user_id} to {new_status}")
        
        return JsonResponse({
            'status': new_status,
            'referral_count': referral_count,
            'message': f'User status changed to {new_status}'
        })
        
    except AppUserProfile.DoesNotExist:
        logger.error(f"User {user_id} not found")
        return JsonResponse({
            'error': 'User not found'
        }, status=404)
    except Exception as e:
        logger.error(f"Error toggling user status: {str(e)}", exc_info=True)
        return JsonResponse({
            'error': 'An error occurred while changing user status'
        }, status=500)

@login_required
def delete_user_direct(request, user_id):
    if request.method == 'POST':
        try:
            # Get the user to be deleted
            user_to_delete = get_object_or_404(User, id=user_id)
            
            # Get the current user's profile
            current_user_profile = UserProfile.objects.get(user=request.user)
            
            # Debug information
            print(f"Current user role: {current_user_profile.role.name}")
            print(f"Is superuser: {request.user.is_superuser}")
            
            # Check if current user has permission (must be a manager or superuser)
            if not request.user.is_superuser and current_user_profile.role.name != 'manager':
                return JsonResponse({
                    'success': False, 
                    'message': f'Permission denied. Your role ({current_user_profile.role.name}) does not allow deleting users.'
                }, status=403)
            
            # Check if user is trying to delete themselves
            if user_to_delete.id == request.user.id:
                return JsonResponse({
                    'success': False, 
                    'message': 'You cannot delete your own account'
                }, status=400)
            
            # Store the user's name for the success message
            user_name = user_to_delete.get_full_name() or user_to_delete.username
            
            # Delete the user (this will cascade delete the UserProfile)
            user_to_delete.delete()
            
            return JsonResponse({
                'success': True, 
                'message': f'User {user_name} was deleted successfully'
            })
            
        except User.DoesNotExist:
            return JsonResponse({
                'success': False, 
                'message': 'User not found'
            }, status=404)
        except Exception as e:
            print(f"Error deleting user: {str(e)}")  # Debug information
            return JsonResponse({
                'success': False, 
                'message': f'Error deleting user: {str(e)}'
            }, status=500)
    
    return JsonResponse({
        'success': False, 
        'message': 'Invalid request method'
    }, status=405)

@login_required
def export_users_excel(request):
    try:
        # Import required models
        from users.models import UserProfile as AppUserProfile, ReferralRelationship
        from main_accounts.models import State, District, Mandal, Village
        from django.db.models import Count
        import logging
        
        logger = logging.getLogger(__name__)
        logger.info("Starting Excel export process")
        
        # Get all normal users with referral count
        users = AppUserProfile.objects.annotate(
            referral_count=Count('referrals_made', distinct=True)
        ).order_by('-created_at')
        
        logger.info(f"Found {users.count()} users to export")

        # Create a new workbook and add a worksheet
        output = BytesIO()
        workbook = xlsxwriter.Workbook(output)
        worksheet = workbook.add_worksheet()

        # Add formats
        bold = workbook.add_format({'bold': True, 'bg_color': '#E5E7EB'})
        date_format = workbook.add_format({'num_format': 'yyyy-mm-dd'})
        wrap_format = workbook.add_format({'text_wrap': True})

        # Write headers
        headers = [
            'User ID', 'First Name', 'Last Name', 'Phone', 'Email',
            'Status', 'State', 'District', 'Mandal', 'Village',
            'Address', 'Pincode', 'Total Referrals', 'Active Referrals',
            'Network Depth', 'Joined Date', 'Last Login'
        ]
        for col, header in enumerate(headers):
            worksheet.write(0, col, header, bold)

        # Write data rows
        for row, user in enumerate(users, start=1):
            try:
                # Get location names
                state_name = State.objects.get(id=user.state).name if user.state else "Not Specified"
            except State.DoesNotExist:
                state_name = "Not Found"
                logger.warning(f"State not found for user {user.id}")
            except Exception as e:
                state_name = "Error"
                logger.error(f"Error getting state for user {user.id}: {str(e)}")
            
            try:
                district_name = District.objects.get(id=user.district).name if user.district else "Not Specified"
            except District.DoesNotExist:
                district_name = "Not Found"
                logger.warning(f"District not found for user {user.id}")
            except Exception as e:
                district_name = "Error"
                logger.error(f"Error getting district for user {user.id}: {str(e)}")
            
            try:
                mandal_name = Mandal.objects.get(id=user.mandal).name if user.mandal else "Not Specified"
            except Mandal.DoesNotExist:
                mandal_name = "Not Found"
                logger.warning(f"Mandal not found for user {user.id}")
            except Exception as e:
                mandal_name = "Error"
                logger.error(f"Error getting mandal for user {user.id}: {str(e)}")
            
            try:
                village_name = Village.objects.get(id=user.village).name if user.village else "Not Specified"
            except Village.DoesNotExist:
                village_name = "Not Found"
                logger.warning(f"Village not found for user {user.id}")
            except Exception as e:
                village_name = "Error"
                logger.error(f"Error getting village for user {user.id}: {str(e)}")

            try:
                # Get referral statistics
                total_referrals = ReferralRelationship.objects.filter(
                    referrer=user,
                    is_converted=True
                ).count()
                
                active_referrals = ReferralRelationship.objects.filter(
                    referrer=user,
                    referee__status='active',
                    is_converted=True
                ).count()

                # Calculate network depth
                def get_network_depth(user, current_depth=0, visited=None):
                    if visited is None:
                        visited = set()
                    
                    if user.id in visited:
                        return current_depth
                        
                    visited.add(user.id)
                    max_depth = current_depth
                    
                    referrals = ReferralRelationship.objects.filter(
                        referrer=user,
                        is_converted=True
                    ).select_related('referee')
                    
                    for referral in referrals:
                        depth = get_network_depth(referral.referee, current_depth + 1, visited)
                        max_depth = max(max_depth, depth)
                    
                    return max_depth

                network_depth = get_network_depth(user)
                
                # Write user data
                col = 0
                worksheet.write(row, col, user.id); col += 1
                worksheet.write(row, col, user.first_name or ''); col += 1
                worksheet.write(row, col, user.last_name or ''); col += 1
                worksheet.write(row, col, user.phone); col += 1
                worksheet.write(row, col, user.email or ''); col += 1
                worksheet.write(row, col, user.status.title()); col += 1
                worksheet.write(row, col, state_name); col += 1
                worksheet.write(row, col, district_name); col += 1
                worksheet.write(row, col, mandal_name); col += 1
                worksheet.write(row, col, village_name); col += 1
                worksheet.write(row, col, user.address or '', wrap_format); col += 1
                worksheet.write(row, col, user.pincode or ''); col += 1
                worksheet.write(row, col, total_referrals); col += 1
                worksheet.write(row, col, active_referrals); col += 1
                worksheet.write(row, col, network_depth); col += 1
                worksheet.write(row, col, user.created_at.strftime('%Y-%m-%d'), date_format); col += 1
                worksheet.write(row, col, user.last_login.strftime('%Y-%m-%d') if user.last_login else 'Never', date_format)
                
                logger.info(f"Successfully wrote data for user {user.id}")
                
            except Exception as e:
                logger.error(f"Error processing user {user.id}: {str(e)}")
                # Continue with next user instead of failing completely
                continue

        # Set column widths
        column_widths = {
            0: 10,  # User ID
            1: 15,  # First Name
            2: 15,  # Last Name
            3: 15,  # Phone
            4: 25,  # Email
            5: 10,  # Status
            6: 20,  # State
            7: 20,  # District
            8: 20,  # Mandal
            9: 20,  # Village
            10: 30, # Address
            11: 10, # Pincode
            12: 15, # Total Referrals
            13: 15, # Active Referrals
            14: 15, # Network Depth
            15: 12, # Joined Date
            16: 12, # Last Login
        }
        
        for col, width in column_widths.items():
            worksheet.set_column(col, col, width)

        # Auto-filter
        worksheet.autofilter(0, 0, 0, len(headers) - 1)

        workbook.close()
        output.seek(0)

        # Generate the response
        response = HttpResponse(
            output.read(),
            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        response['Content-Disposition'] = 'attachment; filename=normal_users_list.xlsx'
        output.close()

        logger.info("Excel export completed successfully")
        return response
        
    except Exception as e:
        logger.error(f"Error exporting users to Excel: {str(e)}", exc_info=True)
        messages.error(request, f"An error occurred while exporting users to Excel: {str(e)}")
        return redirect('normal_users')

@login_required
def export_users_pdf(request):
    try:
        from users.models import UserProfile as AppUserProfile, ReferralRelationship
        from main_accounts.models import State, District, Mandal, Village
        from django.db.models import Count
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.units import inch
        import logging
        
        logger = logging.getLogger(__name__)
        logger.info("Starting PDF export process")

        # Get all normal users with referral count
        users = AppUserProfile.objects.annotate(
            referral_count=Count('referrals_made', distinct=True)
        ).order_by('-created_at')
        
        logger.info(f"Found {users.count()} users to export")

        # Create the response
        response = HttpResponse(content_type='application/pdf')
        response['Content-Disposition'] = 'attachment; filename=normal_users_list.pdf'

        # Create the PDF document
        doc = SimpleDocTemplate(
            response,
            pagesize=landscape(A4),
            rightMargin=30,
            leftMargin=30,
            topMargin=30,
            bottomMargin=30
        )

        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=16,
            spaceAfter=30,
            alignment=1  # Center alignment
        )
        
        header_style = ParagraphStyle(
            'TableHeader',
            parent=styles['Normal'],
            fontSize=8,
            textColor=colors.white,
            alignment=1
        )
        
        cell_style = ParagraphStyle(
            'TableCell',
            parent=styles['Normal'],
            fontSize=8,
            leading=10,
            wordWrap='CJK'
        )

        # Content elements
        elements = []
        
        # Add title
        elements.append(Paragraph("Normal Users List", title_style))
        elements.append(Spacer(1, 20))

        # Prepare table data
        headers = [
            'User ID', 'Name', 'Phone', 'Email', 'Status',
            'Location', 'Address & Pincode',
            'Referrals', 'Network Depth', 'Joined Date'
        ]
        
        # Convert headers to Paragraphs with white background
        header_cells = [Paragraph(header, header_style) for header in headers]
        data = [header_cells]

        # Add user data
        for user in users:
            try:
                # Get location details
                try:
                    state = State.objects.get(id=user.state).name if user.state else "Not Specified"
                except State.DoesNotExist:
                    state = "Not Found"
                except Exception as e:
                    state = "Error"
                    logger.error(f"Error getting state for user {user.id}: {str(e)}")

                try:
                    district = District.objects.get(id=user.district).name if user.district else "Not Specified"
                except District.DoesNotExist:
                    district = "Not Found"
                except Exception as e:
                    district = "Error"
                    logger.error(f"Error getting district for user {user.id}: {str(e)}")

                try:
                    mandal = Mandal.objects.get(id=user.mandal).name if user.mandal else "Not Specified"
                except Mandal.DoesNotExist:
                    mandal = "Not Found"
                except Exception as e:
                    mandal = "Error"
                    logger.error(f"Error getting mandal for user {user.id}: {str(e)}")

                try:
                    village = Village.objects.get(id=user.village).name if user.village else "Not Specified"
                except Village.DoesNotExist:
                    village = "Not Found"
                except Exception as e:
                    village = "Error"
                    logger.error(f"Error getting village for user {user.id}: {str(e)}")

                # Get referral statistics
                total_referrals = ReferralRelationship.objects.filter(
                    referrer=user,
                    is_converted=True
                ).count()
                
                active_referrals = ReferralRelationship.objects.filter(
                    referrer=user,
                    referee__status='active',
                    is_converted=True
                ).count()

                # Calculate network depth
                def get_network_depth(user, current_depth=0, visited=None):
                    if visited is None:
                        visited = set()
                    
                    if user.id in visited:
                        return current_depth
                        
                    visited.add(user.id)
                    max_depth = current_depth
                    
                    referrals = ReferralRelationship.objects.filter(
                        referrer=user,
                        is_converted=True
                    ).select_related('referee')
                    
                    for referral in referrals:
                        depth = get_network_depth(referral.referee, current_depth + 1, visited)
                        max_depth = max(max_depth, depth)
                    
                    return max_depth

                network_depth = get_network_depth(user)

                # Format location
                location = f"State: {state}\nDistrict: {district}\nMandal: {mandal}\nVillage: {village}"
                
                # Format address
                address_info = f"Address: {user.address or 'Not Specified'}\nPincode: {user.pincode or 'Not Specified'}"
                
                # Format referrals
                referrals_info = f"Total: {total_referrals}\nActive: {active_referrals}"

                # Add row data
                row = [
                    Paragraph(str(user.id), cell_style),
                    Paragraph(f"{user.first_name} {user.last_name}".strip() or "Not Specified", cell_style),
                    Paragraph(str(user.phone), cell_style),
                    Paragraph(user.email or "Not Specified", cell_style),
                    Paragraph(user.status.title(), cell_style),
                    Paragraph(location, cell_style),
                    Paragraph(address_info, cell_style),
                    Paragraph(referrals_info, cell_style),
                    Paragraph(str(network_depth), cell_style),
                    Paragraph(user.created_at.strftime('%Y-%m-%d'), cell_style)
                ]
                data.append(row)
                
                logger.info(f"Successfully processed user {user.id} for PDF")
                
            except Exception as e:
                logger.error(f"Error processing user {user.id} for PDF: {str(e)}")
                continue

        # Create table
        table = Table(data, repeatRows=1)
        
        # Add style
        table.setStyle(TableStyle([
            # Headers
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4338CA')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            # Cells
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('TOPPADDING', (0, 1), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            # Zebra stripes
            *[('BACKGROUND', (0, i), (-1, i), colors.HexColor('#F3F4F6')) for i in range(2, len(data), 2)]
        ]))

        # Add table to elements
        elements.append(table)
        
        # Build PDF
        doc.build(elements)
        
        logger.info("PDF export completed successfully")
        return response

    except Exception as e:
        logger.error(f"Error exporting users to PDF: {str(e)}", exc_info=True)
        messages.error(request, f"An error occurred while exporting users to PDF: {str(e)}")
        return redirect('normal_users')

@login_required
def change_password(request):
    if request.method == 'POST':
        try:
            current_password = request.POST.get('current_password')
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')

            # Validate current password
            if not request.user.check_password(current_password):
                messages.error(request, 'Current password is incorrect')
                return redirect('settings')

            # Validate new password
            if len(new_password) < 8:
                messages.error(request, 'New password must be at least 8 characters long')
                return redirect('settings')

            # Check if new password matches confirmation
            if new_password != confirm_password:
                messages.error(request, 'New passwords do not match')
                return redirect('settings')

            # Change the password
            request.user.set_password(new_password)
            request.user.save()

            # Update the session to prevent logout
            update_session_auth_hash(request, request.user)

            messages.success(request, 'Password changed successfully')
            return redirect('settings')

        except Exception as e:
            messages.error(request, f'Error changing password: {str(e)}')
            return redirect('settings')

    return redirect('settings')

@login_required
def help_center_view(request):
    user_profile = UserProfile.objects.get(user=request.user)
    context = {
        'user_profile': user_profile,
        'role': user_profile.role.get_name_display()
    }
    return render(request, 'help/help_center.html', context)

@login_required
def submit_bug_report_view(request):
    user_profile = UserProfile.objects.get(user=request.user)
    
    if request.method == 'POST':
        try:
            # Get form data
            title = request.POST.get('title')
            description = request.POST.get('description')
            bug_type = request.POST.get('bug_type')
            severity = request.POST.get('severity')
            steps = request.POST.get('steps')
            expected_behavior = request.POST.get('expected_behavior')
            actual_behavior = request.POST.get('actual_behavior')
            browser = request.POST.get('browser')
            os = request.POST.get('os')
            additional_info = request.POST.get('additional_info')

            # Validate required fields
            if not all([title, description, bug_type, severity, steps, expected_behavior, actual_behavior, browser, os]):
                messages.error(request, 'Please fill in all required fields')
                return redirect('submit_bug_report')

            # Create new bug report
            bug_report = BugReport.objects.create(
                title=title,
                description=description,
                bug_type=bug_type,
                severity=severity,
                steps_to_reproduce=steps,
                expected_behavior=expected_behavior,
                actual_behavior=actual_behavior,
                browser=browser,
                operating_system=os,
                additional_info=additional_info,
                reporter=request.user
            )
            
            messages.success(request, 'Bug report submitted successfully!')
            return redirect('known_issues')
        except Exception as e:
            messages.error(request, f'Error submitting bug report: {str(e)}')
            return redirect('submit_bug_report')
    
    context = {
        'user_profile': user_profile,
        'role': user_profile.role.get_name_display()
    }
    return render(request, 'help/submit_bug_report.html', context)

@login_required
def known_issues_view(request):
    user_profile = UserProfile.objects.get(user=request.user)
    
    # Get filter parameters
    status = request.GET.get('status')
    severity = request.GET.get('severity')
    bug_type = request.GET.get('type')
    search = request.GET.get('search')
    
    # Start with appropriate bug reports based on user role
    if request.user.is_superuser:
        # Super-admin can see all bug reports
        bug_reports = BugReport.objects.all()
    else:
        # Regular users can only see their own reports
        bug_reports = BugReport.objects.filter(reporter=request.user)
    
    # Apply filters
    if status:
        bug_reports = bug_reports.filter(status=status)
    if severity:
        bug_reports = bug_reports.filter(severity=severity)
    if bug_type:
        bug_reports = bug_reports.filter(bug_type=bug_type)
    if search:
        if request.user.is_superuser:
            # Super-admin can search by reporter name
            bug_reports = bug_reports.filter(
                Q(title__icontains=search) |
                Q(description__icontains=search) |
                Q(reporter__first_name__icontains=search) |
                Q(reporter__last_name__icontains=search)
            )
        else:
            # Regular users can only search in their own reports
            bug_reports = bug_reports.filter(
                Q(title__icontains=search) |
                Q(description__icontains=search)
            )
    
    # Get unique values for filters
    statuses = BugReport.STATUS_CHOICES
    severities = BugReport.SEVERITY_CHOICES
    bug_types = BugReport.TYPE_CHOICES
    
    context = {
        'user_profile': user_profile,
        'role': user_profile.role.get_name_display(),
        'bug_reports': bug_reports,
        'statuses': statuses,
        'severities': severities,
        'bug_types': bug_types,
        'current_filters': {
            'status': status,
            'severity': severity,
            'type': bug_type,
            'search': search
        },
        'is_superuser': request.user.is_superuser
    }
    return render(request, 'help/known_issues.html', context)

@login_required
def bug_report_detail_view(request, report_id):
    bug_report = get_object_or_404(BugReport, id=report_id)
    user_profile = UserProfile.objects.get(user=request.user)
    
    # Check if user has permission to view this bug report
    if not request.user.is_superuser and bug_report.reporter != request.user:
        messages.error(request, 'You do not have permission to view this bug report.')
        return redirect('known_issues')
    
    if request.method == 'POST':
        # Only super-admin can add replies
        if not request.user.is_superuser:
            messages.error(request, 'Only administrators can reply to bug reports.')
            return redirect('bug_report_detail', report_id=report_id)
            
        try:
            message = request.POST.get('message')
            if not message:
                messages.error(request, 'Reply message cannot be empty.')
                return redirect('bug_report_detail', report_id=report_id)
            
            # Create new reply
            BugReportReply.objects.create(
                bug_report=bug_report,
                admin=request.user,
                message=message
            )
            
            # Update bug report status if provided
            new_status = request.POST.get('status')
            if new_status and new_status != bug_report.status:
                bug_report.status = new_status
                bug_report.save()
            
            messages.success(request, 'Reply added successfully.')
            return redirect('bug_report_detail', report_id=report_id)
            
        except Exception as e:
            messages.error(request, f'Error adding reply: {str(e)}')
            return redirect('bug_report_detail', report_id=report_id)
    
    # Get all replies for this bug report, ordered by newest first
    replies = BugReportReply.objects.filter(bug_report=bug_report).order_by('-created_at')
    
    context = {
        'user_profile': user_profile,
        'role': user_profile.role.get_name_display(),
        'bug_report': bug_report,
        'replies': replies,
        'statuses': BugReport.STATUS_CHOICES,
        'is_superuser': request.user.is_superuser
    }
    return render(request, 'help/bug_report_detail.html', context)

@login_required
def category_list(request):
    user_profile = request.user.profile
    
    # Check if user has permission to access categories
    if not user_profile.role.name in ['super_admin', 'manager', 'editor']:
        messages.error(request, "You don't have permission to access this page.")
        return redirect('dashboard')

    # Get categories based on user role
    if user_profile.role.name == 'editor':
        # Editors can only view active categories
        categories = Category.objects.filter(parent=None, is_active=True).order_by('order')
    else:
        # Super admin and managers can view all categories
        categories = Category.objects.filter(parent=None).order_by('order')

    # For superadmin, select related user information
    if user_profile.role.name == 'super_admin':
        categories = categories.select_related('created_by')

    search_query = request.GET.get('search', '')
    if search_query:
        categories = categories.filter(
            Q(name__icontains=search_query) |
            Q(description__icontains=search_query)
        )

    paginator = Paginator(categories, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'user_profile': user_profile,
        'page_obj': page_obj,
        'search_query': search_query,
        'is_editor': user_profile.role.name == 'editor',
        'is_superadmin': user_profile.role.name == 'super_admin',
    }
    return render(request, 'categories/category_list.html', context)

@login_required
def add_category(request):
    user_profile = request.user.profile
    if request.method == 'POST':
        try:
            name = request.POST.get('name')
            description = request.POST.get('description')
            parent_id = request.POST.get('parent')
            image = request.FILES.get('image')
            
            if not name:
                messages.error(request, "Category name is required.")
                return redirect('add_category')
            
            # Create slug from name
            slug = slugify(name)
            
            # Check if parent category exists
            parent = None
            if parent_id:
                parent = Category.objects.get(id=parent_id)
            
            # Get the highest order number and add 1
            highest_order = Category.objects.aggregate(Max('order'))['order__max']
            new_order = 1 if highest_order is None else highest_order + 1
            
            # Create category
            category = Category.objects.create(
                name=name,
                slug=slug,
                description=description,
                parent=parent,
                image=image,
                order=new_order,
                created_by=request.user,
                updated_by=request.user
            )
            
            messages.success(request, f"Category '{category.name}' created successfully.")
            return redirect('category_list')
            
        except Exception as e:
            messages.error(request, f"Error creating category: {str(e)}")
            return redirect('add_category')
    
    # Get parent categories for dropdown
    parent_categories = Category.objects.filter(parent=None)
    context = {
        'user_profile': user_profile,
        'parent_categories': parent_categories
    }
    return render(request, 'categories/add_category.html', context)

@login_required
def edit_category(request, category_id):
    user_profile = request.user.profile
    if not user_profile.role.name in ['super_admin', 'manager']:
        messages.error(request, "You don't have permission to access this page.", extra_tags='category')
        return redirect('dashboard')

    category = get_object_or_404(Category, id=category_id)

    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description')
        parent_id = request.POST.get('parent')
        is_active = request.POST.get('is_active') == 'on'
        image = request.FILES.get('image')

        if not name:
            messages.error(request, "Category name is required.", extra_tags='category')
            return redirect('edit_category', category_id=category_id)

        try:
            # Check if parent category exists and is not the same as current category
            parent = None
            if parent_id:
                parent = Category.objects.get(id=parent_id)
                if parent.id == category.id:
                    messages.error(request, "A category cannot be its own parent.", extra_tags='category')
                    return redirect('edit_category', category_id=category_id)

            # Update category
            category.name = name
            category.description = description
            category.parent = parent
            category.is_active = is_active
            category.updated_by = request.user
            
            # Handle image upload
            if image:
                # Delete old image if it exists
                if category.image:
                    try:
                        category.image.delete()
                    except Exception as e:
                        print(f"Error deleting old image: {e}")
                
                # Save new image
                category.image = image
            
            category.save()

            messages.success(request, f"Category '{category.name}' updated successfully.", extra_tags='category')
            return redirect('category_list')
        except Category.DoesNotExist:
            messages.error(request, "Selected parent category does not exist.", extra_tags='category')
            return redirect('edit_category', category_id=category_id)
        except Exception as e:
            messages.error(request, f"Error updating category: {str(e)}", extra_tags='category')
            return redirect('edit_category', category_id=category_id)

    parent_categories = Category.objects.filter(parent=None).exclude(id=category_id)
    context = {
        'user_profile': user_profile,
        'category': category,
        'parent_categories': parent_categories,
    }
    return render(request, 'categories/edit_category.html', context)

@login_required
def delete_category(request, category_id):
    user_profile = request.user.profile
    if not user_profile.role.name in ['super_admin', 'manager']:
        return JsonResponse({'status': 'error', 'message': 'Permission denied', 'message_type': 'category'})

    category = get_object_or_404(Category, id=category_id)
    
    try:
        category.delete()
        return JsonResponse({
            'status': 'success', 
            'message': f"Category '{category.name}' deleted successfully.",
            'message_type': 'category'
        })
    except Exception as e:
        return JsonResponse({
            'status': 'error', 
            'message': str(e),
            'message_type': 'category'
        })

@login_required
def toggle_category_status(request, category_id):
    user_profile = request.user.profile
    if not user_profile.role.name in ['super_admin', 'manager']:
        return JsonResponse({
            'status': 'error', 
            'message': 'Permission denied',
            'message_type': 'category'
        })

    category = get_object_or_404(Category, id=category_id)
    
    try:
        category.is_active = not category.is_active
        category.updated_by = request.user
        category.save()
        status = 'activated' if category.is_active else 'deactivated'
        return JsonResponse({
            'status': 'success',
            'message': f"Category '{category.name}' {status} successfully.",
            'is_active': category.is_active,
            'message_type': 'category'
        })
    except Exception as e:
        return JsonResponse({
            'status': 'error', 
            'message': str(e),
            'message_type': 'category'
        })

@login_required
def toggle_category_home(request, category_id):
    user_profile = request.user.profile
    if not user_profile.role.name in ['super_admin', 'manager']:
        return JsonResponse({
            'status': 'error', 
            'message': 'Permission denied',
            'message_type': 'category'
        })

    category = get_object_or_404(Category, id=category_id)
    
    try:
        # Toggle home status
        category.home = not category.home
        category.updated_by = request.user
        category.save()
        
        status = 'added to' if category.home else 'removed from'
        return JsonResponse({
            'status': 'success',
            'message': f"Category '{category.name}' {status} home page successfully.",
            'is_home': category.home,
            'message_type': 'category'
        })
    except Exception as e:
        return JsonResponse({
            'status': 'error', 
            'message': str(e),
            'message_type': 'category'
        })

@login_required
def index_view(request):
    user_profile = request.user.profile
    
    # Get statistics
    total_categories = Category.objects.count()
    active_categories = Category.objects.filter(is_active=True).count()
    total_users = UserProfile.objects.count()
    online_users = UserProfile.objects.filter(is_online=True).count()
    
    # Get recent activities (last 5)
    recent_activities = []
    
    # Add category activities
    recent_categories = Category.objects.order_by('-created_at')[:5]
    for category in recent_categories:
        recent_activities.append({
            'icon': 'fa-layer-group',
            'description': f'New category "{category.name}" was created',
            'timestamp': category.created_at
        })
    
    # Add user activities
    recent_users = UserProfile.objects.order_by('-created_at')[:5]
    for user in recent_users:
        recent_activities.append({
            'icon': 'fa-user-plus',
            'description': f'New user {user.user.get_full_name()} joined',
            'timestamp': user.created_at
        })
    
    # Sort activities by timestamp
    recent_activities.sort(key=lambda x: x['timestamp'], reverse=True)
    recent_activities = recent_activities[:5]  # Get only the 5 most recent
    
    context = {
        'user_profile': user_profile,
        'total_categories': total_categories,
        'active_categories': active_categories,
        'total_users': total_users,
        'online_users': online_users,
        'recent_activities': recent_activities,
    }
    return render(request, 'index.html', context)

@login_required
def update_category_order(request):
    if request.method != 'POST':
        return JsonResponse({
            'status': 'error', 
            'message': 'Invalid request method',
            'message_type': 'category'
        })
    
    try:
        data = json.loads(request.body)
        categories = data.get('categories', [])
        
        if not categories:
            return JsonResponse({
                'status': 'error',
                'message': 'No categories provided',
                'message_type': 'category'
            })

        # Validate all category IDs first
        category_ids = [cat['id'] for cat in categories]
        existing_categories = Category.objects.filter(id__in=category_ids)
        if len(existing_categories) != len(categories):
            return JsonResponse({
                'status': 'error',
                'message': 'Some category IDs are invalid',
                'message_type': 'category'
            })

        # Update order for each category
        for category_data in categories:
            category = next(cat for cat in existing_categories if cat.id == category_data['id'])
            category.order = category_data['order']
            category.save()

        return JsonResponse({
            'status': 'success',
            'message': 'Category order updated successfully',
            'message_type': 'category'
        })

    except json.JSONDecodeError:
        return JsonResponse({
            'status': 'error',
            'message': 'Invalid JSON data',
            'message_type': 'category'
        })
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e),
            'message_type': 'category'
        })

@login_required
def add_live_stream(request):
    user_profile = request.user.profile
    
    if request.method == 'POST':
        try:
            title = request.POST.get('title')
            live_url = request.POST.get('live_url')
            category_id = request.POST.get('category')
            is_important = request.POST.get('is_important') == 'on'
            thumbnail = request.FILES.get('thumbnail')

            if not all([title, live_url, category_id]):
                messages.error(request, "Please fill in all required fields.")
                return redirect('add_live_stream')

            category = Category.objects.get(id=category_id)
            
            # If this stream is being marked as important, unmark any other important streams
            if is_important:
                LiveStream.objects.filter(is_important=True).update(is_important=False)
            
            # Create live stream
            live_stream = LiveStream.objects.create(
                title=title,
                live_url=live_url,
                category=category,
                is_important=is_important,
                thumbnail=thumbnail,
                created_by=request.user,
                updated_by=request.user
            )

            messages.success(request, f"Live stream '{live_stream.title}' created successfully.")
            return redirect('live_stream_list')
            
        except Exception as e:
            messages.error(request, f"Error creating live stream: {str(e)}")
            return redirect('add_live_stream')

    # Get active categories for the dropdown
    categories = Category.objects.filter(is_active=True)
    
    context = {
        'user_profile': user_profile,
        'categories': categories,
    }
    return render(request, 'live_streams/add_live_stream.html', context)

@login_required
def live_stream_list(request):
    # Get user profile
    user_profile = request.user.profile

    # Get all live streams
    live_streams = LiveStream.objects.all().order_by('order', '-created_at')
    categories = Category.objects.filter(is_active=True)

    # Apply filters
    search_query = request.GET.get('search', '')
    selected_category = request.GET.get('category', '')
    selected_status = request.GET.get('status', '')

    if search_query:
        live_streams = live_streams.filter(
            Q(title__icontains=search_query) |
            Q(category__name__icontains=search_query)
        )

    if selected_category:
        live_streams = live_streams.filter(category_id=selected_category)

    if selected_status:
        is_active = selected_status == 'active'
        live_streams = live_streams.filter(is_active=is_active)

    # Pagination
    paginator = Paginator(live_streams, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'user_profile': user_profile,
        'page_obj': page_obj,
        'categories': categories,
        'search_query': search_query,
        'selected_category': selected_category,
        'selected_status': selected_status,
    }

    return render(request, 'live_streams/live_stream_list.html', context)

@login_required
def edit_live_stream(request, live_stream_id):
    user_profile = request.user.profile
    live_stream = get_object_or_404(LiveStream, id=live_stream_id)
    
    if request.method == 'POST':
        try:
            title = request.POST.get('title')
            live_url = request.POST.get('live_url')
            category_id = request.POST.get('category')
            is_important = request.POST.get('is_important') == 'on'
            is_active = request.POST.get('is_active') == 'on'
            thumbnail = request.FILES.get('thumbnail')

            if not all([title, live_url, category_id]):
                messages.error(request, "Please fill in all required fields.")
                return redirect('edit_live_stream', live_stream_id=live_stream_id)

            category = Category.objects.get(id=category_id)
            
            # If this stream is being marked as important, unmark all other streams first
            if is_important:
                LiveStream.objects.exclude(id=live_stream_id).filter(is_important=True).update(is_important=False)
            
            # Update live stream
            live_stream.title = title
            live_stream.live_url = live_url
            live_stream.category = category
            live_stream.is_important = is_important
            live_stream.is_active = is_active
            live_stream.updated_by = request.user
            
            if thumbnail:
                live_stream.thumbnail = thumbnail
                
            live_stream.save()

            messages.success(request, f"Live stream '{live_stream.title}' updated successfully.")
            return redirect('live_stream_list')
            
        except Exception as e:
            messages.error(request, f"Error updating live stream: {str(e)}")
            return redirect('edit_live_stream', live_stream_id=live_stream_id)

    # Get active categories for the dropdown
    categories = Category.objects.filter(is_active=True)
    
    context = {
        'user_profile': user_profile,
        'live_stream': live_stream,
        'categories': categories,
    }
    return render(request, 'live_streams/edit_live_stream.html', context)

@login_required
def delete_live_stream(request, live_stream_id):
    user_profile = request.user.profile
    live_stream = get_object_or_404(LiveStream, id=live_stream_id)
    
    if request.method == 'POST':
        try:
            title = live_stream.title
            live_stream.delete()
            messages.success(request, f"Live stream '{title}' deleted successfully.")
            return redirect('live_stream_list')
        except Exception as e:
            messages.error(request, f"Error deleting live stream: {str(e)}")
            return redirect('live_stream_list')
    
    return redirect('live_stream_list')

@login_required
def toggle_live_stream_status(request, live_stream_id):
    user_profile = request.user.profile
    live_stream = get_object_or_404(LiveStream, id=live_stream_id)
    
    if request.method == 'POST':
        try:
            live_stream.is_active = not live_stream.is_active
            live_stream.updated_by = request.user
            live_stream.save()
            
            status = 'activated' if live_stream.is_active else 'deactivated'
            messages.success(request, f"Live stream '{live_stream.title}' {status} successfully.")
        except Exception as e:
            messages.error(request, f"Error updating status: {str(e)}")
    
    return redirect('live_stream_list')

@login_required
def update_live_stream_order(request):
    if request.method != 'POST':
        return JsonResponse({
            'status': 'error', 
            'message': 'Invalid request method'
        })
    
    try:
        data = json.loads(request.body)
        live_streams = data.get('live_streams', [])
        
        if not live_streams:
            return JsonResponse({
                'status': 'error',
                'message': 'No live streams provided'
            })

        # Validate all live stream IDs first
        live_stream_ids = [ls['id'] for ls in live_streams]
        existing_live_streams = LiveStream.objects.filter(id__in=live_stream_ids)
        if len(existing_live_streams) != len(live_streams):
            return JsonResponse({
                'status': 'error',
                'message': 'Some live stream IDs are invalid'
            })

        # Update order for each live stream
        for live_stream_data in live_streams:
            live_stream = next(ls for ls in existing_live_streams if ls.id == live_stream_data['id'])
            live_stream.order = live_stream_data['order']
            live_stream.save()

        return JsonResponse({
            'status': 'success',
            'message': 'Live stream order updated successfully'
        })

    except json.JSONDecodeError:
        return JsonResponse({
            'status': 'error',
            'message': 'Invalid JSON data'
        })
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        })

@login_required
def frontend_categories(request):
    """
    ఫ్రంట్‌ఎండ్ కోసం కేటగిరీలను తీసుకొచ్చే API - కేవలం హోమ్ పేజీ కేటగిరీలు మాత్రమే
    """
    try:
        # Get only active categories marked for home page
        categories = Category.objects.filter(is_active=True, home=True).order_by('order')
        
        # Process categories
        categories_data = []
        for category in categories:
            category_info = {
                'id': category.id,
                'name': category.name,
                'slug': category.slug,
                'description': category.description,
                'icon': category.icon,
                'subcategories': []
            }
            
            # Get only active subcategories
            subcategories = category.subcategories.filter(is_active=True)
            for subcategory in subcategories:
                subcategory_info = {
                    'id': subcategory.id,
                    'name': subcategory.name,
                    'slug': subcategory.slug,
                    'description': subcategory.description,
                    'icon': subcategory.icon
                }
                category_info['subcategories'].append(subcategory_info)
            
            categories_data.append(category_info)
        
        return Response({
            'status': 'success',
            'message': 'Home categories fetched successfully',
            'data': categories_data
        })
        
    except Exception as e:
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=500)

class CategoryViewSet(viewsets.ModelViewSet):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_permissions(self):
        """
        Override to allow public access for listing active categories
        """
        if self.action == 'active':
            return [permissions.AllowAny()]
        return [permissions.IsAuthenticated()]

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user, updated_by=self.request.user)

    def perform_update(self, serializer):
        serializer.save(updated_by=self.request.user)

    @action(detail=False, methods=['get'])
    def active(self, request):
        active_categories = Category.objects.filter(is_active=True)
        serializer = self.get_serializer(active_categories, many=True, context={'request': request})
        return Response(serializer.data)

class LiveStreamViewSet(viewsets.ModelViewSet):
    queryset = LiveStream.objects.all().order_by('order', '-created_at')
    serializer_class = LiveStreamSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user, updated_by=self.request.user)

    def perform_update(self, serializer):
        serializer.save(updated_by=self.request.user)

    @action(detail=False, methods=['get'])
    def active(self, request):
        active_streams = LiveStream.objects.filter(is_active=True).order_by('order', '-created_at')
        serializer = self.get_serializer(active_streams, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def important(self, request):
        important_streams = LiveStream.objects.filter(is_important=True, is_active=True).order_by('order', '-created_at')
        serializer = self.get_serializer(important_streams, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'], permission_classes=[AllowAny])
    def by_category(self, request):
        category_id = request.query_params.get('category_id')
        if not category_id:
            return Response({"error": "category_id is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        streams = LiveStream.objects.filter(category_id=category_id, is_active=True).order_by('order', '-created_at')
        serializer = self.get_serializer(streams, many=True)
        return Response(serializer.data)

@api_view(['GET'])
@permission_classes([AllowAny])
def frontend_categories(request):
    """
    ఫ్రంట్‌ఎండ్ కోసం కేటగిరీలను తీసుకొచ్చే API - కేవలం హోమ్ పేజీ కేటగిరీలు మాత్రమే
    """
    try:
        # Get only active categories marked for home page
        categories = Category.objects.filter(is_active=True, home=True).order_by('order')
        
        # Process categories
        categories_data = []
        for category in categories:
            category_info = {
                'id': category.id,
                'name': category.name,
                'slug': category.slug,
                'description': category.description,
                'icon': category.icon,
                'subcategories': []
            }
            
            # Get only active subcategories
            subcategories = category.subcategories.filter(is_active=True)
            for subcategory in subcategories:
                subcategory_info = {
                    'id': subcategory.id,
                    'name': subcategory.name,
                    'slug': subcategory.slug,
                    'description': subcategory.description,
                    'icon': subcategory.icon
                }
                category_info['subcategories'].append(subcategory_info)
            
            categories_data.append(category_info)
        
        return Response({
            'status': 'success',
            'message': 'Home categories fetched successfully',
            'data': categories_data
        })
        
    except Exception as e:
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=500)

class StateViewSet(viewsets.ModelViewSet):
    queryset = State.objects.all()
    serializer_class = StateSerializer
    permission_classes = [AllowAny]  # Allow public access by default

    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            return [permissions.IsAuthenticated()]  # Require authentication for modifications
        return [AllowAny()]  # Allow public access for list and retrieve

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return DetailedStateSerializer
        return StateSerializer

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user, updated_by=self.request.user)

    def perform_update(self, serializer):
        serializer.save(updated_by=self.request.user)

    @action(detail=False, methods=['get'])
    def active(self, request):
        active_states = State.objects.filter(is_active=True).order_by('order', 'name')
        serializer = self.get_serializer(active_states, many=True)
        return Response({
            'status': 'success',
            'message': 'States fetched successfully',
            'data': serializer.data
        })

class DistrictViewSet(viewsets.ModelViewSet):
    queryset = District.objects.all()
    serializer_class = DistrictSerializer
    permission_classes = [AllowAny]  # Allow public access

    def get_serializer_class(self):
        if self.action in ['retrieve', 'list']:
            return DetailedDistrictSerializer
        return self.serializer_class

    def perform_create(self, serializer):
        serializer.save()

    def perform_update(self, serializer):
        serializer.save()

    @action(detail=False, methods=['get'])
    def by_state(self, request):
        state_id = request.query_params.get('state_id')
        if state_id:
            districts = District.objects.filter(state_id=state_id)
            serializer = self.get_serializer(districts, many=True)
            return Response({'status': 'success', 'data': serializer.data})
        return Response({'status': 'error', 'message': 'state_id is required'}, status=400)

class ConstituencyViewSet(viewsets.ModelViewSet):
    queryset = Constituency.objects.all()
    serializer_class = ConstituencySerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return DetailedConstituencySerializer
        return ConstituencySerializer

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user, updated_by=self.request.user)

    def perform_update(self, serializer):
        serializer.save(updated_by=self.request.user)

    @action(detail=False, methods=['get'])
    def by_district(self, request):
        district_id = request.query_params.get('district_id')
        if not district_id:
            return Response({"error": "district_id is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        constituencies = Constituency.objects.filter(district_id=district_id, is_active=True).order_by('order', 'name')
        serializer = self.get_serializer(constituencies, many=True)
        return Response(serializer.data)

class MandalViewSet(viewsets.ModelViewSet):
    queryset = Mandal.objects.all()
    serializer_class = MandalSerializer
    permission_classes = [AllowAny]  # Allow public access

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return DetailedMandalSerializer
        return self.serializer_class

    def perform_create(self, serializer):
        serializer.save()

    def perform_update(self, serializer):
        serializer.save()

    @action(detail=False, methods=['get'])
    def by_constituency(self, request):
        constituency_id = request.query_params.get('constituency_id')
        if constituency_id:
            mandals = Mandal.objects.filter(constituency_id=constituency_id, is_active=True).order_by('order', 'name')
            serializer = self.get_serializer(mandals, many=True)
            return Response({'status': 'success', 'data': serializer.data})
        return Response({'status': 'error', 'message': 'constituency_id is required'}, status=400)

class VillageViewSet(viewsets.ModelViewSet):
    queryset = Village.objects.all()
    serializer_class = VillageSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return DetailedVillageSerializer
        return VillageSerializer

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user, updated_by=self.request.user)

    def perform_update(self, serializer):
        serializer.save(updated_by=self.request.user)

    @action(detail=False, methods=['get'])
    def by_mandal(self, request):
        mandal_id = request.query_params.get('mandal_id')
        if not mandal_id:
            return Response({"error": "mandal_id is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        villages = Village.objects.filter(mandal_id=mandal_id, is_active=True).order_by('order', 'name')
        serializer = self.get_serializer(villages, many=True)
        return Response(serializer.data)

class RegionalVideoViewSet(viewsets.ModelViewSet):
    queryset = RegionalVideo.objects.all()
    serializer_class = RegionalVideoSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user, updated_by=self.request.user)

    def perform_update(self, serializer):
        serializer.save(updated_by=self.request.user)

    @action(detail=False, methods=['get'])
    def by_location(self, request):
        state_id = request.query_params.get('state_id')
        district_id = request.query_params.get('district_id')
        constituency_id = request.query_params.get('constituency_id')
        mandal_id = request.query_params.get('mandal_id')
        village_id = request.query_params.get('village_id')
        category = request.query_params.get('category')
        is_trending = request.query_params.get('trending') == 'true'
        is_hd = request.query_params.get('hd') == 'true'

        videos = RegionalVideo.objects.filter(is_active=True)

        if state_id:
            videos = videos.filter(state_id=state_id)
        if district_id:
            videos = videos.filter(district_id=district_id)
        if constituency_id:
            videos = videos.filter(constituency_id=constituency_id)
        if mandal_id:
            videos = videos.filter(mandal_id=mandal_id)
        if village_id:
            videos = videos.filter(village_id=village_id)
        if category:
            videos = videos.filter(category=category)
        if is_trending:
            videos = videos.filter(is_trending=True)
        if is_hd:
            videos = videos.filter(is_hd=True)

        videos = videos.order_by('order', '-created_at')
        serializer = self.get_serializer(videos, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def increment_views(self, request, pk=None):
        video = self.get_object()
        video.views_count += 1
        video.save()
        return Response({'status': 'success', 'views_count': video.views_count})

@login_required
def state_list(request):
    user_profile = request.user.profile
    
    # Get all states with their districts count
    states = State.objects.all().order_by('order', 'name')
    
    # Apply search filter
    search_query = request.GET.get('search', '')
    if search_query:
        states = states.filter(name__icontains=search_query)
    
    # Pagination
    paginator = Paginator(states, 10)  # Show 10 states per page
    page_number = request.GET.get('page')
    states = paginator.get_page(page_number)
    
    context = {
        'user_profile': user_profile,
        'states': states,
        'search_query': search_query,
        'is_editor': user_profile.role.name == 'editor'
    }
    return render(request, 'regional/state_list.html', context)

@login_required
def add_state(request):
    logger.info("Entering add_state view")
    user_profile = request.user.profile
    if user_profile.role.name == 'editor':
        messages.error(request, "You don't have permission to add states.")
        return redirect('state_list')
    
    if request.method == 'POST':
        logger.info("Processing POST request")
        try:
            name = request.POST.get('name')
            logger.info(f"Name received: {name}")
            
            image = request.FILES.get('image')
            logger.info(f"Image received: {image}")
            
            is_active = request.POST.get('is_active') == 'on'
            logger.info(f"Is active: {is_active}")
            
            if not name:
                messages.error(request, "State name is required.")
                return redirect('add_state')
            
            # Get the highest order number and add 1
            highest_order = State.objects.aggregate(Max('order'))['order__max']
            new_order = (highest_order or 0) + 1
            
            logger.info("Creating state object")
            state = State.objects.create(
                name=name,
                image=image,
                is_active=is_active,
                order=new_order,
                created_by=request.user,
                updated_by=request.user
            )
            logger.info(f"State created with ID: {state.id}")
            
            if image:
                logger.info(f"Image URL: {state.image.url}")
            
            messages.success(request, f"State '{state.name}' created successfully.")
            logger.info("Redirecting to state_list")
            return redirect('state_list')
            
        except Exception as e:
            logger.error(f"Error creating state: {str(e)}")
            messages.error(request, f"Error creating state: {str(e)}")
            return redirect('add_state')
    
    context = {
        'user_profile': user_profile
    }
    return render(request, 'regional/add_state.html', context)

@login_required
def edit_state(request, state_id):
    user_profile = request.user.profile
    if user_profile.role.name == 'editor':
        messages.error(request, "You don't have permission to edit states.")
        return redirect('state_list')
    
    state = get_object_or_404(State, id=state_id)
    
    if request.method == 'POST':
        try:
            name = request.POST.get('name')
            image = request.FILES.get('image')
            is_active = request.POST.get('is_active') == 'on'
            
            if not name:
                messages.error(request, "State name is required.")
                return redirect('edit_state', state_id=state_id)
            
            state.name = name
            if image:
                state.image = image
            state.is_active = is_active
            state.updated_by = request.user
            state.save()
            
            messages.success(request, f"State '{state.name}' updated successfully.")
            return redirect('state_list')
            
        except Exception as e:
            messages.error(request, f"Error updating state: {str(e)}")
            return redirect('edit_state', state_id=state_id)
    
    context = {
        'user_profile': user_profile,
        'state': state
    }
    return render(request, 'regional/edit_state.html', context)

@login_required
def delete_state(request, state_id):
    if request.method == 'POST':
        try:
            state = get_object_or_404(State, id=state_id)
            name = state.name
            state.delete()
            return JsonResponse({
                'status': 'success',
                'message': f"State '{name}' deleted successfully."
            })
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            })
    return JsonResponse({
        'status': 'error',
        'message': 'Invalid request method'
    })

@login_required
def toggle_state_status(request, state_id):
    user_profile = request.user.profile
    state = get_object_or_404(State, id=state_id)
    
    if request.method == 'POST':
        try:
            state.is_active = not state.is_active
            state.updated_by = request.user
            state.save()
            
            status = 'activated' if state.is_active else 'deactivated'
            messages.success(request, f"State '{state.name}' {status} successfully.")
        except Exception as e:
            messages.error(request, f"Error updating status: {str(e)}")
    
    return redirect('state_list')

@login_required
def district_list(request):
    user_profile = request.user.profile
    
    # Get all districts with their state info
    districts = District.objects.select_related('state').all().order_by('order', 'name')
    
    # Apply search filter
    search_query = request.GET.get('search', '')
    if search_query:
        districts = districts.filter(
            Q(name__icontains=search_query) |
            Q(state__name__icontains=search_query)
        )
    
    # Pagination
    paginator = Paginator(districts, 10)  # Show 10 districts per page
    page_number = request.GET.get('page')
    districts = paginator.get_page(page_number)
    
    context = {
        'user_profile': user_profile,
        'districts': districts,
        'search_query': search_query,
        'is_editor': user_profile.role.name == 'editor'
    }
    return render(request, 'regional/district_list.html', context)

@login_required
def add_district(request):
    user_profile = request.user.profile
    if user_profile.role.name == 'editor':
        messages.error(request, "You don't have permission to add districts.")
        return redirect('district_list')
    
    if request.method == 'POST':
        try:
            name = request.POST.get('name')
            state_id = request.POST.get('state')
            image = request.FILES.get('image')
            is_active = request.POST.get('is_active') == 'on'
            
            if not all([name, state_id]):
                messages.error(request, "District name and state are required.")
                return redirect('add_district')
            
            state = State.objects.get(id=state_id)
            
            # Get the highest order number and add 1
            highest_order = District.objects.filter(state=state).aggregate(Max('order'))['order__max']
            new_order = (highest_order or 0) + 1
            
            district = District.objects.create(
                name=name,
                state=state,
                image=image,
                is_active=is_active,
                order=new_order,
                created_by=request.user,
                updated_by=request.user
            )
            
            messages.success(request, f"District '{district.name}' created successfully.")
            return redirect('district_list')
            
        except State.DoesNotExist:
            messages.error(request, "Selected state does not exist.")
            return redirect('add_district')
        except Exception as e:
            messages.error(request, f"Error creating district: {str(e)}")
            return redirect('add_district')
    
    # Get active states for the dropdown
    states = State.objects.filter(is_active=True).order_by('name')
    
    context = {
        'user_profile': user_profile,
        'states': states
    }
    return render(request, 'regional/add_district.html', context)

@login_required
def edit_district(request, district_id):
    user_profile = request.user.profile
    if user_profile.role.name == 'editor':
        messages.error(request, "You don't have permission to edit districts.")
        return redirect('district_list')
    
    district = get_object_or_404(District, id=district_id)
    
    if request.method == 'POST':
        try:
            name = request.POST.get('name')
            state_id = request.POST.get('state')
            image = request.FILES.get('image')
            is_active = request.POST.get('is_active') == 'on'
            
            if not all([name, state_id]):
                messages.error(request, "District name and state are required.")
                return redirect('edit_district', district_id=district_id)
            
            state = State.objects.get(id=state_id)
            
            district.name = name
            district.state = state
            if image:
                district.image = image
            district.is_active = is_active
            district.updated_by = request.user
            district.save()
            
            messages.success(request, f"District '{district.name}' updated successfully.")
            return redirect('district_list')
            
        except State.DoesNotExist:
            messages.error(request, "Selected state does not exist.")
            return redirect('edit_district', district_id=district_id)
        except Exception as e:
            messages.error(request, f"Error updating district: {str(e)}")
            return redirect('edit_district', district_id=district_id)
    
    # Get active states for the dropdown
    states = State.objects.filter(is_active=True).order_by('name')
    
    context = {
        'user_profile': user_profile,
        'district': district,
        'states': states
    }
    return render(request, 'regional/edit_district.html', context)

@login_required
def delete_district(request, district_id):
    if request.method == 'POST':
        try:
            district = get_object_or_404(District, id=district_id)
            name = district.name
            district.delete()
            return JsonResponse({
                'status': 'success',
                'message': f"District '{name}' deleted successfully."
            })
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            })
    return JsonResponse({
        'status': 'error',
        'message': 'Invalid request method'
    })

@login_required
def toggle_district_status(request, district_id):
    user_profile = request.user.profile
    district = get_object_or_404(District, id=district_id)
    
    if request.method == 'POST':
        try:
            district.is_active = not district.is_active
            district.updated_by = request.user
            district.save()
            
            status = 'activated' if district.is_active else 'deactivated'
            messages.success(request, f"District '{district.name}' {status} successfully.")
        except Exception as e:
            messages.error(request, f"Error updating status: {str(e)}")
    
    return redirect('district_list')

@login_required
def add_constituency(request):
    user_profile = request.user.profile
    if user_profile.role.name == 'editor':
        messages.error(request, "You don't have permission to add constituencies.")
        return redirect('constituency_list')
    
    if request.method == 'POST':
        try:
            name = request.POST.get('name')
            district_id = request.POST.get('district')
            image = request.FILES.get('image')
            is_active = request.POST.get('is_active') == 'on'
            
            if not all([name, district_id]):
                messages.error(request, "Constituency name and district are required.")
                return redirect('add_constituency')
            
            district = District.objects.get(id=district_id)
            
            # Get the highest order number and add 1
            highest_order = Constituency.objects.filter(district=district).aggregate(Max('order'))['order__max']
            new_order = (highest_order or 0) + 1
            
            constituency = Constituency.objects.create(
                name=name,
                district=district,
                image=image,
                is_active=is_active,
                order=new_order,
                created_by=request.user,
                updated_by=request.user
            )
            
            messages.success(request, f"Constituency '{constituency.name}' created successfully.")
            return redirect('constituency_list')
            
        except District.DoesNotExist:
            messages.error(request, "Selected district does not exist.")
            return redirect('add_constituency')
        except Exception as e:
            messages.error(request, f"Error creating constituency: {str(e)}")
            return redirect('add_constituency')
    
    # Get active states for the dropdown
    states = State.objects.filter(is_active=True).order_by('name')
    
    context = {
        'user_profile': user_profile,
        'states': states
    }
    return render(request, 'regional/add_constituency.html', context)

@login_required
def edit_constituency(request, constituency_id):
    user_profile = request.user.profile
    if user_profile.role.name == 'editor':
        messages.error(request, "You don't have permission to edit constituencies.")
        return redirect('constituency_list')
    
    constituency = get_object_or_404(Constituency, id=constituency_id)
    
    if request.method == 'POST':
        try:
            name = request.POST.get('name')
            district_id = request.POST.get('district')
            image = request.FILES.get('image')
            is_active = request.POST.get('is_active') == 'on'
            
            if not all([name, district_id]):
                messages.error(request, "Constituency name and district are required.")
                return redirect('edit_constituency', constituency_id=constituency_id)
            
            district = District.objects.get(id=district_id)
            
            constituency.name = name
            constituency.district = district
            if image:
                constituency.image = image
            constituency.is_active = is_active
            constituency.updated_by = request.user
            constituency.save()
            
            messages.success(request, f"Constituency '{constituency.name}' updated successfully.")
            return redirect('constituency_list')
            
        except District.DoesNotExist:
            messages.error(request, "Selected district does not exist.")
            return redirect('edit_constituency', constituency_id=constituency_id)
        except Exception as e:
            messages.error(request, f"Error updating constituency: {str(e)}")
            return redirect('edit_constituency', constituency_id=constituency_id)
    
    # Get active districts for the dropdown
    districts = District.objects.filter(is_active=True).select_related('state').order_by('state__name', 'state__name', 'name')
    
    # Get active states for the dropdown
    states = State.objects.filter(is_active=True).order_by('name')
    
    context = {
        'user_profile': user_profile,
        'constituency': constituency,
        'districts': districts,
        'states': states
    }
    return render(request, 'regional/edit_constituency.html', context)

@login_required
def delete_constituency(request, constituency_id):
    if request.method == 'POST':
        try:
            constituency = get_object_or_404(Constituency, id=constituency_id)
            name = constituency.name
            constituency.delete()
            return JsonResponse({
                'status': 'success',
                'message': f"Constituency '{name}' deleted successfully."
            })
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            })
    return JsonResponse({
        'status': 'error',
        'message': 'Invalid request method'
    })

@login_required
def toggle_constituency_status(request, constituency_id):
    if request.method == 'POST':
        try:
            constituency = get_object_or_404(Constituency, id=constituency_id)
            
            # Toggle the status
            constituency.is_active = not constituency.is_active
            constituency.updated_by = request.user
            constituency.save()
            
            # Return success response
            status = 'activated' if constituency.is_active else 'deactivated'
            messages.success(request, f"Constituency '{constituency.name}' {status} successfully.")
            
            # If it's an AJAX request, return JSON response
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'status': 'success',
                    'message': f"Constituency '{constituency.name}' {status} successfully.",
                    'is_active': constituency.is_active
                })
            
            # Otherwise redirect back to the list page
            return redirect('constituency_list')
            
        except Exception as e:
            messages.error(request, f"Error updating constituency status: {str(e)}")
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'status': 'error',
                    'message': str(e)
                }, status=500)
            return redirect('constituency_list')
            
    return JsonResponse({
        'status': 'error',
        'message': 'Invalid request method'
    }, status=400)

@login_required
def mandal_list(request):
    user_profile = request.user.profile
    
    # Get all mandals with their constituency, district and state info
    mandals = Mandal.objects.select_related('constituency', 'constituency__district', 'constituency__district__state').all().order_by('order', 'name')
    
    # Apply search filter
    search_query = request.GET.get('search', '')
    if search_query:
        mandals = mandals.filter(
            Q(name__icontains=search_query) |
            Q(constituency__name__icontains=search_query) |
            Q(constituency__district__name__icontains=search_query) |
            Q(constituency__district__state__name__icontains=search_query)
        )
    
    # Pagination
    paginator = Paginator(mandals, 10)  # Show 10 mandals per page
    page_number = request.GET.get('page')
    mandals = paginator.get_page(page_number)
    
    context = {
        'user_profile': user_profile,
        'mandals': mandals,
        'search_query': search_query,
        'is_editor': user_profile.role.name == 'editor'
    }
    return render(request, 'regional/mandal_list.html', context)

@login_required
def add_mandal(request):
    user_profile = request.user.profile
    if user_profile.role.name == 'editor':
        messages.error(request, "You don't have permission to add mandals.")
        return redirect('mandal_list')
    
    if request.method == 'POST':
        try:
            name = request.POST.get('name')
            constituency_id = request.POST.get('constituency')
            image = request.FILES.get('image')
            is_active = request.POST.get('is_active') == 'on'
            
            if not all([name, constituency_id]):
                messages.error(request, "Mandal name and constituency are required.")
                return redirect('add_mandal')
            
            constituency = Constituency.objects.get(id=constituency_id)
            
            # Get the highest order number and add 1
            highest_order = Mandal.objects.filter(constituency=constituency).aggregate(Max('order'))['order__max']
            new_order = (highest_order or 0) + 1
            
            mandal = Mandal.objects.create(
                name=name,
                constituency=constituency,
                image=image,
                is_active=is_active,
                order=new_order,
                created_by=request.user,
                updated_by=request.user
            )
            
            messages.success(request, f"Mandal '{mandal.name}' created successfully.")
            return redirect('mandal_list')
            
        except Constituency.DoesNotExist:
            messages.error(request, "Selected constituency does not exist.")
            return redirect('add_mandal')
        except Exception as e:
            messages.error(request, f"Error creating mandal: {str(e)}")
            return redirect('add_mandal')
    
    # Get active states for the dropdown
    states = State.objects.filter(is_active=True).order_by('name')
    
    context = {
        'user_profile': user_profile,
        'states': states
    }
    return render(request, 'regional/add_mandal.html', context)

@login_required
def edit_mandal(request, mandal_id):
    user_profile = request.user.profile
    if user_profile.role.name == 'editor':
        messages.error(request, "You don't have permission to edit mandals.")
        return redirect('mandal_list')
    
    mandal = get_object_or_404(Mandal, id=mandal_id)
    
    if request.method == 'POST':
        try:
            name = request.POST.get('name')
            constituency_id = request.POST.get('constituency')
            image = request.FILES.get('image')
            is_active = request.POST.get('is_active') == 'on'
            
            if not all([name, constituency_id]):
                messages.error(request, "Mandal name and constituency are required.")
                return redirect('edit_mandal', mandal_id=mandal_id)
            
            constituency = Constituency.objects.get(id=constituency_id)
            
            mandal.name = name
            mandal.constituency = constituency
            if image:
                mandal.image = image
            mandal.is_active = is_active
            mandal.updated_by = request.user
            mandal.save()
            
            messages.success(request, f"Mandal '{mandal.name}' updated successfully.")
            return redirect('mandal_list')
            
        except Constituency.DoesNotExist:
            messages.error(request, "Selected constituency does not exist.")
            return redirect('edit_mandal', mandal_id=mandal_id)
        except Exception as e:
            messages.error(request, f"Error updating mandal: {str(e)}")
            return redirect('edit_mandal', mandal_id=mandal_id)
    
    # Get active states for the dropdown
    states = State.objects.filter(is_active=True).order_by('name')
    
    context = {
        'user_profile': user_profile,
        'mandal': mandal,
        'states': states,
    }
    return render(request, 'regional/edit_mandal.html', context)

@login_required
def delete_mandal(request, mandal_id):
    if request.method == 'POST':
        try:
            mandal = get_object_or_404(Mandal, id=mandal_id)
            name = mandal.name
            mandal.delete()
            return JsonResponse({
                'status': 'success',
                'message': f"Mandal '{name}' deleted successfully."
            })
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            })
    return JsonResponse({
        'status': 'error',
        'message': 'Invalid request method'
    })

@login_required
@require_http_methods(["POST"])
def toggle_mandal_status(request, mandal_id):
    try:
        mandal = get_object_or_404(Mandal, id=mandal_id)
        
        # Check if user has permission
        user_profile = request.user.profile
        if user_profile.role.name == 'editor':
            return JsonResponse({
                'status': 'error',
                'message': "You don't have permission to change mandal status."
            }, status=403)
        
        # Toggle the status
        mandal.is_active = not mandal.is_active
        mandal.updated_by = request.user
        mandal.save()
        
        status = 'activated' if mandal.is_active else 'deactivated'
        return JsonResponse({
            'status': 'success',
            'message': f"Mandal '{mandal.name}' {status} successfully.",
            'is_active': mandal.is_active
        })
    except Mandal.DoesNotExist:
        return JsonResponse({
            'status': 'error',
            'message': 'Mandal not found'
        }, status=404)
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)

@login_required
def village_list(request):
    user_profile = request.user.profile
    
    # Get all villages with their mandal, constituency, district and state info
    villages = Village.objects.select_related(
        'mandal', 
        'mandal__constituency', 
        'mandal__constituency__district', 
        'mandal__constituency__district__state'
    ).all().order_by('order', 'name')
    
    # Apply search filter
    search_query = request.GET.get('search', '')
    if search_query:
        villages = villages.filter(
            Q(name__icontains=search_query) |
            Q(mandal__name__icontains=search_query) |
            Q(mandal__constituency__name__icontains=search_query) |
            Q(mandal__constituency__district__name__icontains=search_query) |
            Q(mandal__constituency__district__state__name__icontains=search_query)
        )
    
    # Pagination
    paginator = Paginator(villages, 10)  # Show 10 villages per page
    page_number = request.GET.get('page')
    villages = paginator.get_page(page_number)
    
    context = {
        'user_profile': user_profile,
        'villages': villages,
        'search_query': search_query,
        'is_editor': user_profile.role.name == 'editor'
    }
    return render(request, 'regional/village_list.html', context)

@login_required
def add_village(request):
    user_profile = request.user.profile
    if user_profile.role.name == 'editor':
        messages.error(request, "You don't have permission to add villages.")
        return redirect('village_list')
    
    if request.method == 'POST':
        try:
            name = request.POST.get('name')
            mandal_id = request.POST.get('mandal')
            image = request.FILES.get('image')
            is_active = request.POST.get('is_active') == 'on'
            
            if not all([name, mandal_id]):
                messages.error(request, "Village name and mandal are required.")
                return redirect('add_village')
            
            mandal = Mandal.objects.get(id=mandal_id)
            
            # Get the highest order number and add 1
            highest_order = Village.objects.filter(mandal=mandal).aggregate(Max('order'))['order__max']
            new_order = (highest_order or 0) + 1
            
            village = Village.objects.create(
                name=name,
                mandal=mandal,
                image=image,
                is_active=is_active,
                order=new_order,
                created_by=request.user,
                updated_by=request.user
            )
            
            messages.success(request, f"Village '{village.name}' created successfully.")
            return redirect('village_list')
            
        except Mandal.DoesNotExist:
            messages.error(request, "Selected mandal does not exist.")
            return redirect('add_village')
        except Exception as e:
            messages.error(request, f"Error creating village: {str(e)}")
            return redirect('add_village')
    
    # Get active states for the dropdown
    states = State.objects.filter(is_active=True).order_by('name')
    
    context = {
        'user_profile': user_profile,
        'states': states
    }
    return render(request, 'regional/add_village.html', context)

@login_required
def edit_village(request, village_id):
    user_profile = request.user.profile
    if user_profile.role.name == 'editor':
        messages.error(request, "You don't have permission to edit villages.")
        return redirect('village_list')
    
    village = get_object_or_404(Village, id=village_id)
    
    if request.method == 'POST':
        try:
            name = request.POST.get('name')
            mandal_id = request.POST.get('mandal')
            image = request.FILES.get('image')
            is_active = request.POST.get('is_active') == 'on'
            
            if not all([name, mandal_id]):
                messages.error(request, "Village name and mandal are required.")
                return redirect('edit_village', village_id=village_id)
            
            mandal = Mandal.objects.get(id=mandal_id)
            
            village.name = name
            village.mandal = mandal
            if image:
                village.image = image
            village.is_active = is_active
            village.updated_by = request.user
            village.save()
            
            messages.success(request, f"Village '{village.name}' updated successfully.")
            return redirect('village_list')
            
        except Mandal.DoesNotExist:
            messages.error(request, "Selected mandal does not exist.")
            return redirect('edit_village', village_id=village_id)
        except Exception as e:
            messages.error(request, f"Error updating village: {str(e)}")
            return redirect('edit_village', village_id=village_id)
    
    # Get active mandals for the dropdown
    mandals = Mandal.objects.filter(is_active=True).select_related(
        'constituency', 
        'constituency__district', 
        'constituency__district__state'
    ).order_by(
        'constituency__district__state__name',
        'constituency__district__name',
        'constituency__name',
        'name'
    )
    
    context = {
        'user_profile': user_profile,
        'village': village,
        'mandals': mandals
    }
    return render(request, 'regional/edit_village.html', context)

@login_required
def delete_village(request, village_id):
    if request.method == 'POST':
        try:
            village = get_object_or_404(Village, id=village_id)
            name = village.name
            village.delete()
            return JsonResponse({
                'status': 'success',
                'message': f"Village '{name}' deleted successfully."
            })
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            })
    return JsonResponse({
        'status': 'error',
        'message': 'Invalid request method'
    })

@login_required
def toggle_village_status(request, village_id):
    if request.method == 'POST':
        try:
            village = get_object_or_404(Village, id=village_id)
            village.is_active = not village.is_active
            village.save()
            
            status = 'activated' if village.is_active else 'deactivated'
            return JsonResponse({
                'status': 'success',
                'message': f"Village '{village.name}' {status} successfully.",
                'is_active': village.is_active
            })
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            })
    return JsonResponse({
        'status': 'error',
        'message': 'Invalid request method'
    })

@login_required
def constituency_list(request):
    user_profile = request.user.profile
    
    # Get all constituencies with their district and state info
    constituencies = Constituency.objects.select_related('district', 'district__state').all().order_by('order', 'name')
    
    # Apply search filter
    search_query = request.GET.get('search', '')
    if search_query:
        constituencies = constituencies.filter(
            Q(name__icontains=search_query) |
            Q(district__name__icontains=search_query) |
            Q(district__state__name__icontains=search_query)
        )
    
    # Pagination
    paginator = Paginator(constituencies, 10)  # Show 10 constituencies per page
    page_number = request.GET.get('page')
    constituencies = paginator.get_page(page_number)
    
    context = {
        'user_profile': user_profile,
        'constituencies': constituencies,
        'search_query': search_query,
        'is_editor': user_profile.role.name == 'editor'
    }
    return render(request, 'regional/constituency_list.html', context)

@login_required
def reorder_states(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=400)
    
    try:
        data = json.loads(request.body)
        state_ids = data.get('state_ids', [])
        
        if not state_ids:
            return JsonResponse({'status': 'error', 'message': 'No state IDs provided'}, status=400)
        
        print(f"Reordering states with IDs: {state_ids}")  # Debug log
        
        # Update order for each state
        for index, state_id in enumerate(state_ids, start=1):
            try:
                state = State.objects.get(id=state_id)
                state.order = index
                state.save()
                print(f"Updated state {state.name} to order {index}")  # Debug log
            except State.DoesNotExist:
                print(f"State with ID {state_id} not found")  # Debug log
                continue
        
        return JsonResponse({'status': 'success'})
    except json.JSONDecodeError as e:
        print(f"JSON decode error: {str(e)}")  # Debug log
        return JsonResponse({'status': 'error', 'message': 'Invalid JSON data'}, status=400)
    except Exception as e:
        print(f"Error in reorder_states: {str(e)}")  # Debug log
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

@login_required
def reorder_districts(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=400)
    
    try:
        data = json.loads(request.body)
        state_districts = data.get('state_districts', {})
        
        if not state_districts:
            return JsonResponse({
                'status': 'error',
                'message': 'No district data provided'
            }, status=400)
        
        print(f"Reordering districts: {state_districts}")  # Debug log
        
        # Update order for each district within each state
        for state_id, district_ids in state_districts.items():
            print(f"Processing state {state_id} with districts: {district_ids}")  # Debug log
            
            # Verify all districts exist and belong to the state
            districts = District.objects.filter(id__in=district_ids, state_id=state_id)
            if len(districts) != len(district_ids):
                print(f"Some districts not found or don't belong to state {state_id}")  # Debug log
                return JsonResponse({
                    'status': 'error',
                    'message': f'Some districts not found or do not belong to state {state_id}'
                }, status=400)
            
            # Update order for each district
            for index, district_id in enumerate(district_ids, start=1):
                print(f"Setting order {index} for district {district_id}")  # Debug log
                District.objects.filter(id=district_id, state_id=state_id).update(order=index)
        
        print("District reordering completed successfully")  # Debug log
        return JsonResponse({'status': 'success'})
        
    except json.JSONDecodeError as e:
        print(f"JSON decode error: {str(e)}")  # Debug log
        return JsonResponse({
            'status': 'error',
            'message': 'Invalid JSON data'
        }, status=400)
    except Exception as e:
        print(f"Error in reorder_districts: {str(e)}")  # Debug log
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)

@login_required
def get_districts_by_state(request, state_id):
    try:
        districts = District.objects.filter(state_id=state_id, is_active=True).values('id', 'name').order_by('name')
        return JsonResponse(list(districts), safe=False)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def get_constituencies_by_district(request, district_id):
    try:
        constituencies = Constituency.objects.filter(district_id=district_id, is_active=True).values('id', 'name').order_by('name')
        return JsonResponse(list(constituencies), safe=False)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def get_mandals_by_constituency(request, constituency_id):
    try:
        mandals = Mandal.objects.filter(constituency_id=constituency_id, is_active=True).values('id', 'name').order_by('name')
        return JsonResponse(list(mandals), safe=False)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@api_view(['GET'])
@permission_classes([AllowAny])
def frontend_states(request):
    """
    ఫ్రంట్‌ఎండ్ కోసం యాక్టివ్ స్టేట్స్ లిస్ట్ తీసుకొచ్చే API
    """
    try:
        # Get only active states ordered by their display order
        states = State.objects.filter(is_active=True).order_by('order', 'name')
        
        # Process states
        states_data = []
        for state in states:
            state_info = {
                'id': state.id,
                'name': state.name,
                'image': request.build_absolute_uri(state.image.url) if state.image else None,
                'districts_count': state.districts.filter(is_active=True).count()
            }
            states_data.append(state_info)
        
        return Response({
            'status': 'success',
            'message': 'States fetched successfully',
            'data': states_data
        })
        
    except Exception as e:
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=500)

@login_required
def reorder_constituencies(request):
    if request.method == 'POST':
        try:
            constituency_order = json.loads(request.body)
            with transaction.atomic():
                for order_data in constituency_order:
                    constituency_id = order_data.get('id')
                    new_order = order_data.get('order')
                    if constituency_id and new_order is not None:
                        Constituency.objects.filter(id=constituency_id).update(order=new_order)
                return JsonResponse({'status': 'success', 'message': 'Constituency order updated successfully'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})

@login_required
def reorder_mandals(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=400)
    
    try:
        data = json.loads(request.body)
        order_data = data
        
        if not order_data:
            return JsonResponse({
                'status': 'error',
                'message': 'No mandal data provided'
            }, status=400)
        
        print(f"Reordering mandals: {order_data}")  # Debug log
        
        # Update order for each mandal
        with transaction.atomic():
            for item in order_data:
                mandal_id = item.get('id')
                new_order = item.get('order')
                
                if not all([mandal_id, new_order]):
                    continue
                
                print(f"Setting order {new_order} for mandal {mandal_id}")  # Debug log
                Mandal.objects.filter(id=mandal_id).update(order=new_order)
        
        print("Mandal reordering completed successfully")  # Debug log
        return JsonResponse({
            'status': 'success',
            'message': 'Mandal order updated successfully'
        })
        
    except json.JSONDecodeError as e:
        print(f"JSON decode error: {str(e)}")  # Debug log
        return JsonResponse({
            'status': 'error',
            'message': 'Invalid JSON data'
        }, status=400)
    except Exception as e:
        print(f"Error reordering mandals: {str(e)}")  # Debug log
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)

@login_required
def reorder_villages(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            for item in data:
                village = get_object_or_404(Village, id=item['id'])
                village.order = item['order']
                village.save()
            
            return JsonResponse({
                'status': 'success',
                'message': 'Village order updated successfully.'
            })
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            })
    return JsonResponse({
        'status': 'error',
        'message': 'Invalid request method'
    })

@api_view(['GET'])
@permission_classes([AllowAny])
def frontend_districts(request):
    state_id = request.GET.get('state_id')
    if state_id:
        districts = District.objects.filter(state_id=state_id, is_active=True).order_by('order', 'name')
        serializer = DetailedDistrictSerializer(districts, many=True, context={'request': request})
        return Response({'status': 'success', 'data': serializer.data})
    return Response({'status': 'error', 'message': 'state_id is required'}, status=400)

@api_view(['GET'])
@permission_classes([AllowAny])
def frontend_constituencies(request):
    district_id = request.GET.get('district_id')
    constituencies = Constituency.objects.filter(is_active=True)
    if district_id:
        constituencies = constituencies.filter(district_id=district_id)
    constituencies = constituencies.order_by('order')
    serializer = ConstituencySerializer(constituencies, many=True, context={'request': request})
    return Response({
        'status': 'success',
        'data': serializer.data
    })

@api_view(['GET'])
@permission_classes([AllowAny])
def frontend_mandals(request):
    constituency_id = request.GET.get('constituency_id')
    mandals = Mandal.objects.filter(is_active=True)
    if constituency_id:
        mandals = mandals.filter(constituency_id=constituency_id)
    mandals = mandals.order_by('order')
    serializer = MandalSerializer(mandals, many=True)
    return Response({
        'status': 'success',
        'data': serializer.data
    })

@api_view(['GET'])
@permission_classes([AllowAny])
def frontend_villages(request):
    mandal_id = request.GET.get('mandal_id')
    villages = Village.objects.filter(is_active=True)
    if mandal_id:
        villages = villages.filter(mandal_id=mandal_id)
    villages = villages.order_by('order')
    serializer = VillageSerializer(villages, many=True)
    return Response({
        'status': 'success',
        'data': serializer.data
    })

@login_required
def normal_users_view(request):
    # Get current user's profile
    user_profile = UserProfile.objects.get(user=request.user)
    
    # Get all normal users (users from the users app)
    from users.models import UserProfile as AppUserProfile, ReferralRelationship, UserSubscription
    from django.db.models import Q, Count, OuterRef, Subquery
    from main_accounts.models import State, District
    from django.utils import timezone
    
    # Get latest active subscription subquery
    latest_subscription = UserSubscription.objects.filter(
        user=OuterRef('pk'),
        is_active=True,
        payment_status='success',
        start_date__lte=timezone.now(),
        end_date__gte=timezone.now()
    ).order_by('-created_at')

    # Base queryset with referral count and subscription info
    users = AppUserProfile.objects.annotate(
        referral_count=Count('referrals_made', distinct=True),
        current_plan=Subquery(latest_subscription.values('plan_name')[:1]),
        plan_end_date=Subquery(latest_subscription.values('end_date')[:1])
    ).order_by('-created_at')
    
    # Get query parameters for filtering
    search_query = request.GET.get('search', '')
    status_filter = request.GET.get('status', '')
    page_size = request.GET.get('page_size', '10')  # Default to 10 items per page
    
    # Apply filters
    if search_query:
        users = users.filter(
            Q(phone__icontains=search_query) |
            Q(first_name__icontains=search_query) |
            Q(last_name__icontains=search_query)
        )
    
    if status_filter:
        is_active = status_filter == 'active'
        users = users.filter(status='active' if is_active else 'inactive')
    
    # Get state and district names for each user
    users_with_locations = []
    for user in users:
        try:
            state_name = State.objects.get(id=user.state).name if user.state else "Not Specified"
        except State.DoesNotExist:
            state_name = "Not Found"
            
        try:
            district_name = District.objects.get(id=user.district).name if user.district else "Not Specified"
        except District.DoesNotExist:
            district_name = "Not Found"
            
        user.state_name = state_name
        user.district_name = district_name
        users_with_locations.append(user)
    
    # Handle pagination
    items_per_page = None if page_size == 'all' else int(page_size)
    if items_per_page:
        paginator = Paginator(users_with_locations, items_per_page)
        page_number = request.GET.get('page')
        normal_users = paginator.get_page(page_number)
    else:
        # If showing all items, create a dummy paginator with all items on one page
        paginator = Paginator(users_with_locations, len(users_with_locations))
        normal_users = paginator.get_page(1)
    
    context = {
        'user_profile': user_profile,
        'normal_users': normal_users,
        'search_query': search_query,
        'status_filter': status_filter,
        'page_size': page_size,  # Add page_size to context
    }
    
    return render(request, 'dashboard/normal_users.html', context)

@login_required
@require_http_methods(["GET"])
def get_referral_tree(request, user_id):
    try:
        from users.models import UserProfile as AppUserProfile, ReferralRelationship
        
        # Get the root user
        root_user = AppUserProfile.objects.get(id=user_id)
        
        def get_user_data(user, is_selected=False):
            # Get direct referral count for this user
            direct_referrals = ReferralRelationship.objects.filter(
                referrer=user,
                is_converted=True
            ).count()
            
            return {
                'id': user.id,
                'first_name': user.first_name or '',
                'last_name': user.last_name or '',
                'phone': user.phone,
                'email': user.email,
                'is_active': user.status == 'active',
                'is_selected': is_selected,
                'joined_date': user.created_at.strftime('%Y-%m-%d'),
                'referral_count': direct_referrals,
                'children': []
            }
        
        def build_tree(user, depth=0, max_depth=3):
            if depth > max_depth:
                return None
                
            user_data = get_user_data(user, depth == 0)
            
            # Get direct referrals that are converted
            referrals = ReferralRelationship.objects.filter(
                referrer=user,
                is_converted=True
            ).select_related('referee')
            
            # Recursively build tree for each referral
            for referral in referrals:
                child_data = build_tree(referral.referee, depth + 1, max_depth)
                if child_data:
                    user_data['children'].append(child_data)
            
            return user_data
        
        # Build the complete tree
        tree_data = build_tree(root_user)
        
        return JsonResponse(tree_data)
        
    except AppUserProfile.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def get_user_details(request, user_id):
    try:
        # Import required models
        from users.models import UserProfile as AppUserProfile, ReferralRelationship
        from main_accounts.models import State, District, Mandal, Village
        import logging
        
        logger = logging.getLogger(__name__)
        logger.info(f"Fetching details for user_id: {user_id}")
        
        # Get user profile
        user = get_object_or_404(AppUserProfile, id=user_id)
        logger.info(f"Found user: {user.phone}")
        
        # Get location details
        try:
            state_name = State.objects.get(id=int(user.state)).name if user.state and user.state.isdigit() else "Not Specified"
            district_name = District.objects.get(id=int(user.district)).name if user.district and user.district.isdigit() else "Not Specified"
            mandal_name = Mandal.objects.get(id=int(user.mandal)).name if user.mandal and user.mandal.isdigit() else "Not Specified"
            village_name = Village.objects.get(id=int(user.village)).name if user.village and user.village.isdigit() else "Not Specified"
            logger.info("Location details fetched successfully")
        except (State.DoesNotExist, District.DoesNotExist, Mandal.DoesNotExist, Village.DoesNotExist) as loc_error:
            logger.error(f"Error fetching location details: {str(loc_error)}")
            if isinstance(loc_error, State.DoesNotExist):
                state_name = "Not Found"
            if isinstance(loc_error, District.DoesNotExist):
                district_name = "Not Found"
            if isinstance(loc_error, Mandal.DoesNotExist):
                mandal_name = "Not Found"
            if isinstance(loc_error, Village.DoesNotExist):
                village_name = "Not Found"
        except ValueError as val_error:
            logger.error(f"Invalid location ID: {str(val_error)}")
            state_name = user.state or "Not Specified"
            district_name = user.district or "Not Specified"
            mandal_name = user.mandal or "Not Specified"
            village_name = user.village or "Not Specified"
        
        # Get referral statistics
        try:
            total_referrals = ReferralRelationship.objects.filter(
                referrer=user,
                is_converted=True
            ).count()
            active_referrals = ReferralRelationship.objects.filter(
                referrer=user,
                referee__status='active',
                is_converted=True
            ).count()
            logger.info(f"Referral stats: total={total_referrals}, active={active_referrals}")
        except Exception as ref_error:
            logger.error(f"Error fetching referral stats: {str(ref_error)}")
            total_referrals = 0
            active_referrals = 0
        
        # Calculate network depth
        def get_network_depth(user, current_depth=0, visited=None):
            if visited is None:
                visited = set()
            
            if user.id in visited:
                return current_depth
                
            visited.add(user.id)
            max_depth = current_depth
            
            try:
                direct_referrals = ReferralRelationship.objects.filter(
                    referrer=user,
                    is_converted=True
                ).select_related('referee')
                
                for referral in direct_referrals:
                    depth = get_network_depth(referral.referee, current_depth + 1, visited)
                    max_depth = max(max_depth, depth)
                
                return max_depth
            except Exception as depth_error:
                logger.error(f"Error calculating network depth: {str(depth_error)}")
                return current_depth
        
        network_depth = get_network_depth(user)
        logger.info(f"Network depth: {network_depth}")
        
        # Get recent activities
        activities = []
        try:
            # Add login activity if available
            if hasattr(user, 'last_login') and user.last_login:
                activities.append({
                    'type': 'login',
                    'description': 'Last login',
                    'timestamp': user.last_login.isoformat() if user.last_login else None
                })
            
            # Add referral activities
            recent_referrals = ReferralRelationship.objects.filter(
                referrer=user
            ).order_by('-created_at')[:5]
            
            for referral in recent_referrals:
                activities.append({
                    'type': 'referral',
                    'description': f'Referred user {referral.referred.phone}',
                    'timestamp': referral.created_at.isoformat() if referral.created_at else None
                })
            
            # Sort activities by timestamp
            activities.sort(key=lambda x: x['timestamp'] if x['timestamp'] else '', reverse=True)
            logger.info(f"Fetched {len(activities)} activities")
        except Exception as act_error:
            logger.error(f"Error fetching activities: {str(act_error)}")
        
        # Prepare response data
        data = {
            'id': user.id,
            'first_name': user.first_name or '',
            'last_name': user.last_name or '',
            'phone': user.phone,
            'email': user.email or '',
            'profile_picture': user.profile_picture.url if user.profile_picture else None,
            'status': user.status,
            'created_at': user.created_at.isoformat() if user.created_at else None,
            'referral_code': user.referral.referral_code if hasattr(user, 'referral') else None,
            'state_name': state_name,
            'district_name': district_name,
            'mandal_name': mandal_name,
            'village_name': village_name,
            'pincode': user.pincode or "Not Specified",
            'address': user.address or "Not Specified",
            'total_referrals': total_referrals,
            'active_referrals': active_referrals,
            'network_depth': network_depth,
            'activities': activities
        }
        
        logger.info("Successfully prepared response data")
        return JsonResponse(data)
        
    except Exception as e:
        logger.error(f"Error in get_user_details: {str(e)}")
        return JsonResponse({
            'error': 'An error occurred while fetching user details',
            'details': str(e)
        }, status=500)

@login_required
@require_http_methods(["POST"])
def delete_user(request, user_id):
    try:
        # Get the current user's profile first
        try:
            current_user_profile = UserProfile.objects.get(user=request.user)
        except UserProfile.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'Your user profile is not properly configured'
            }, status=403)

        # Check if the user has the permission to delete
        if not request.user.is_superuser and current_user_profile.role.name != 'manager':
            return JsonResponse({
                'status': 'error',
                'message': 'You do not have permission to delete users'
            }, status=403)

        # Get the user to delete from the users app
        from users.models import UserProfile as AppUserProfile
        try:
            user = AppUserProfile.objects.get(id=user_id)
        except AppUserProfile.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'User not found or has already been deleted'
            }, status=404)
        
        # Store user info for response
        user_info = {
            'id': user.id,
            'name': f"{user.first_name} {user.last_name}".strip() or user.phone,
        }
        
        try:
            # Delete the user
            user.delete()
            
            # Return success response
            return JsonResponse({
                'status': 'success',
                'message': f'User {user_info["name"]} has been deleted successfully',
                'user': user_info
            })
            
        except Exception as delete_error:
            print(f"Error deleting user: {str(delete_error)}")  # Debug information
            return JsonResponse({
                'status': 'error',
                'message': f'Error deleting user: {str(delete_error)}'
            }, status=500)
            
    except Exception as e:
        print(f"Unexpected error in delete_user: {str(e)}")  # Debug information
        return JsonResponse({
            'status': 'error',
            'message': f'Unexpected error: {str(e)}'
        }, status=500)

@login_required
def referral_settings(request):
    """
    View to display referral bonus settings
    """
    from users.models import ReferralRelationship
    from django.db.models import Count

    user_profile = UserProfile.objects.get(user=request.user)
    bonus_levels = ReferralBonus.objects.filter(is_active=True).order_by('level')
    
    # Get total active referrals count
    total_active_referrals = ReferralRelationship.objects.filter(
        is_converted=True,
        referee__status='active'
    ).count()

    return render(request, 'settings/referral_settings.html', {
        'bonus_levels': bonus_levels,
        'user_profile': user_profile,
        'total_active_referrals': total_active_referrals
    })

def update_referral_settings(request):
    """
    View to update referral bonus settings
    """
    if request.method == 'POST':
        try:
            # Get all active bonus levels
            bonus_levels = ReferralBonus.objects.filter(is_active=True)
            
            for bonus in bonus_levels:
                # Get new values from form
                new_amount = request.POST.get(f'amount_{bonus.id}')
                new_description = request.POST.get(f'description_{bonus.id}')
                
                if new_amount and new_description:
                    # Convert amount to Decimal and validate
                    try:
                        amount = Decimal(new_amount)
                        if amount < 0 or amount > 100:
                            raise ValueError("Percentage must be between 0 and 100")
                            
                        # Update bonus level
                        bonus.amount = amount
                        bonus.description = new_description
                        bonus.save()
                    except (ValueError, decimal.InvalidOperation) as e:
                        messages.error(request, f'Invalid amount for Level {bonus.level}: {str(e)}')
                        return redirect('referral_settings')
            
            messages.success(request, 'Referral bonus levels updated successfully')
        except Exception as e:
            messages.error(request, f'Error updating bonus levels: {str(e)}')
    
    return redirect('referral_settings')

@login_required
def withdrawal_limits(request):
    """View for withdrawal limits settings page"""
    from users.models import WithdrawalSettings
    
    settings = WithdrawalSettings.get_settings()
    context = {
        'min_withdrawal': settings.min_withdrawal_amount,
        'max_withdrawal': settings.max_withdrawal_amount,
        'daily_limit': settings.max_daily_withdrawals,
        'user_profile': request.user.profile  # Add user profile to context
    }
    return render(request, 'settings/withdrawal_limits.html', context)

@login_required
def update_withdrawal_limits(request):
    """Update withdrawal limits"""
    from users.models import WithdrawalSettings, UserProfile
    
    if request.method == 'POST':
        try:
            # Get the values from the form
            min_withdrawal = request.POST.get('min_withdrawal', '')
            max_withdrawal = request.POST.get('max_withdrawal', '')
            daily_limit = request.POST.get('daily_limit', '')

            # Validate that values are provided
            if not min_withdrawal or not max_withdrawal or not daily_limit:
                messages.error(request, 'All fields are required')
                return redirect('withdrawal_limits')

            # Convert to proper decimal/integer values
            try:
                min_withdrawal = float(min_withdrawal)
                max_withdrawal = float(max_withdrawal)
                daily_limit = int(daily_limit)
            except ValueError:
                messages.error(request, 'Please enter valid numbers')
                return redirect('withdrawal_limits')
            
            # Validate minimum withdrawal
            if min_withdrawal <= 0:
                messages.error(request, 'Minimum withdrawal amount must be greater than 0')
                return redirect('withdrawal_limits')
            
            # Validate maximum withdrawal    
            if max_withdrawal <= min_withdrawal:
                messages.error(request, f'Maximum withdrawal amount (₹{max_withdrawal}) must be greater than minimum withdrawal amount (₹{min_withdrawal})')
                return redirect('withdrawal_limits')
            
            # Validate daily limit    
            if daily_limit <= 0:
                messages.error(request, 'Daily withdrawal limit must be greater than 0')
                return redirect('withdrawal_limits')
            
            if daily_limit > 10:  # Adding a reasonable upper limit
                messages.error(request, 'Daily withdrawal limit cannot exceed 10')
                return redirect('withdrawal_limits')
            
            # Get or create settings
            settings = WithdrawalSettings.get_settings()
            
            # Get user profile
            try:
                user_profile = UserProfile.objects.get(email=request.user.email)
            except UserProfile.DoesNotExist:
                messages.error(request, 'User profile not found')
                return redirect('withdrawal_limits')
            
            # Update settings
            settings.min_withdrawal_amount = min_withdrawal
            settings.max_withdrawal_amount = max_withdrawal
            settings.max_daily_withdrawals = daily_limit
            settings.updated_by = user_profile
            settings.save()
            
            messages.success(request, 'Withdrawal limits updated successfully')
            
        except Exception as e:
            messages.error(request, f'Error updating withdrawal limits: {str(e)}')
            
    return redirect('withdrawal_limits')

@login_required
def withdrawal_management(request):
    # Get withdrawal settings
    withdrawal_settings = WithdrawalSettings.get_settings()

    # Get all withdrawal transactions
    transactions = WalletTransaction.objects.filter(
        transaction_type='WITHDRAWAL'
    ).select_related(
        'wallet__user',
        'bank_account'
    ).order_by('-created_at')

    # Calculate statistics
    today = timezone.now().date()
    today_start = datetime.combine(today, datetime.min.time())
    today_end = datetime.combine(today, datetime.max.time())

    total_withdrawals_today = WalletTransaction.objects.filter(
        transaction_type='WITHDRAWAL',
        created_at__range=(today_start, today_end)
    ).aggregate(total=Sum('amount'))['total'] or 0

    status_counts = WalletTransaction.objects.filter(
        transaction_type='WITHDRAWAL'
    ).values('status').annotate(count=Count('id'))

    status_dict = {item['status']: item['count'] for item in status_counts}
    
    # Paginate transactions
    paginator = Paginator(transactions, 10)
    page = request.GET.get('page')
    transactions = paginator.get_page(page)

    context = {
        'withdrawal_settings': withdrawal_settings,
        'transactions': transactions,
        'total_withdrawals_today': total_withdrawals_today,
        'completed_withdrawals_count': status_dict.get('COMPLETED', 0),
        'pending_withdrawals_count': status_dict.get('PENDING', 0),
        'failed_withdrawals_count': status_dict.get('FAILED', 0),
        'user_profile': request.user.profile  # Add user profile to context
    }

    return render(request, 'payments/withdrawal_management.html', context)

@login_required
@require_POST
def update_withdrawal_settings(request):
    try:
        settings = WithdrawalSettings.get_settings()
        settings.min_withdrawal_amount = request.POST.get('min_withdrawal_amount')
        settings.max_withdrawal_amount = request.POST.get('max_withdrawal_amount')
        settings.max_daily_withdrawals = request.POST.get('max_daily_withdrawals')
        settings.updated_by = request.user
        settings.save()
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
@require_POST
def update_withdrawal_status(request):
    """
    Update the status of a withdrawal transaction.
    """
    try:
        transaction_id = request.POST.get('transaction_id')
        new_status = request.POST.get('status')

        if not transaction_id or not new_status:
            return JsonResponse({
                'success': False,
                'error': 'Missing required parameters'
            }, status=400)

        # Get the transaction
        transaction = get_object_or_404(WalletTransaction, id=transaction_id)

        # Only allow updating pending transactions
        if transaction.status != 'PENDING':
            return JsonResponse({
                'success': False,
                'error': 'Can only update pending transactions'
            }, status=400)

        # Update the status
        transaction.status = new_status
        transaction.processed_by = request.user
        transaction.processed_at = timezone.now()
        transaction.save()

        # If the transaction was rejected, refund the amount to the user's wallet
        if new_status == 'FAILED':
            wallet = transaction.wallet
            wallet.balance += transaction.amount
            wallet.save()

        return JsonResponse({
            'success': True,
            'message': f'Transaction {new_status.lower()}'
        })

    except WalletTransaction.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'Transaction not found'
        }, status=404)
    except Exception as e:
        logging.error(f"Error updating withdrawal status: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'An error occurred while updating the status'
        }, status=500)

@login_required
def get_withdrawal_details(request, transaction_id):
    """
    Get detailed information about a withdrawal transaction.
    """
    try:
        logging.info(f"Fetching withdrawal details for transaction ID: {transaction_id}")
        
        # Get the transaction with related user info
        transaction = get_object_or_404(
            WalletTransaction.objects.select_related(
                'wallet__user',
                'wallet__user__userprofile',
                'bank_account',
                'processed_by'
            ),
            id=transaction_id,
            transaction_type='WITHDRAWAL'  # Only get withdrawal transactions
        )

        logging.info(f"Found transaction: {transaction.id}, status: {transaction.status}")
        
        # Log related objects to check if they're properly loaded
        logging.info(f"User: {transaction.wallet.user.get_full_name()}")
        logging.info(f"Bank Account: {transaction.bank_account.bank_name if transaction.bank_account else 'None'}")
        
        context = {'transaction': transaction}
        response = render(request, 'payments/withdrawal_details.html', context)
        logging.info(f"Rendered template with status code: {response.status_code}")
        return response

    except WalletTransaction.DoesNotExist:
        logging.error(f"Transaction not found: {transaction_id}")
        return HttpResponse(
            '<div class="text-center text-red-600 p-6">'
            '<i class="fas fa-exclamation-circle text-3xl mb-2"></i>'
            '<p>Transaction not found</p>'
            '<button onclick="closeDetailsModal()" class="mt-4 px-4 py-2 bg-gray-200 text-gray-700 rounded hover:bg-gray-300">'
            'Close'
            '</button>'
            '</div>'
        )
    except Exception as e:
        logging.error(f"Error getting withdrawal details for {transaction_id}: {str(e)}", exc_info=True)
        return HttpResponse(
            '<div class="text-center text-red-600 p-6">'
            '<i class="fas fa-exclamation-circle text-3xl mb-2"></i>'
            '<p>Error loading transaction details</p>'
            '<p class="text-sm mt-2">Please try again later</p>'
            '<button onclick="closeDetailsModal()" class="mt-4 px-4 py-2 bg-gray-200 text-gray-700 rounded hover:bg-gray-300">'
            'Close'
            '</button>'
            '</div>'
        )

class VideoViewSet(viewsets.ModelViewSet):
    queryset = Video.objects.all()
    serializer_class = VideoSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        data = serializer.data

        # Convert MP4 URL to HLS URL
        if data.get('video_url') and data['video_url'].endswith('.mp4'):
            mp4_url = data['video_url']
            # Replace .mp4 with .m3u8 in the same path
            hls_url = mp4_url.replace('.mp4', '.m3u8')
            data['hls_url'] = hls_url
            data['video_url'] = hls_url  # Replace MP4 with HLS URL

        # Add promo fields if they exist
        if hasattr(instance, 'promo_hls_url'):
            data['promo_hls_url'] = instance.promo_hls_url
        if hasattr(instance, 'promo_image'):
            data['promo_image'] = instance.promo_image

        return Response(data)

    def get_queryset(self):
        queryset = Video.objects.filter(is_active=True)
        category = self.request.query_params.get('category', None)
        video_type = self.request.query_params.get('type', None)

        if category:
            queryset = queryset.filter(category_id=category)
        if video_type:
            queryset = queryset.filter(video_type=video_type)

        return queryset

    @action(detail=True, methods=['post'])
    def increment_views(self, request, pk=None):
        video = self.get_object()
        video.views_count = F('views_count') + 1
        video.save()
        return Response({'status': 'views updated'})

    @action(detail=True, methods=['post'])
    def rent(self, request, pk=None):
        video = self.get_object()
        duration = request.data.get('duration')
        
        try:
            price = video.prices.get(rental_duration=duration, is_active=True)
            expiry_date = timezone.now() + timezone.timedelta(hours=duration)
            
            user_video = UserVideo.objects.create(
                user=request.user,
                video=video,
                purchase_type='rental',
                expiry_date=expiry_date,
                amount_paid=price.rental_price,
                is_active=True
            )
            
            serializer = UserVideoSerializer(user_video, context={'request': request})
            return Response(serializer.data)
        except VideoPrice.DoesNotExist:
            return Response(
                {'error': 'Invalid rental duration or price not set'},
                status=status.HTTP_400_BAD_REQUEST
            )

class VideoPriceViewSet(viewsets.ModelViewSet):
    queryset = VideoPrice.objects.filter(is_active=True)
    serializer_class = VideoPriceSerializer
    permission_classes = [permissions.IsAuthenticated]

class UserVideoViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = UserVideoSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return UserVideo.objects.filter(
            user=self.request.user,
            is_active=True
        ).select_related('video')

@login_required
def video_list(request):
    # Get user profile
    user_profile = request.user.profile

    # Get search parameters
    search_query = request.GET.get('search', '')
    selected_category = request.GET.get('category', '')
    selected_type = request.GET.get('type', '')

    # Base queryset
    videos = Video.objects.select_related('category', 'created_by')

    # Apply filters
    if search_query:
        videos = videos.filter(
            Q(title__icontains=search_query) |
            Q(category__name__icontains=search_query)
        )
    if selected_category:
        videos = videos.filter(category_id=selected_category)
    if selected_type:
        videos = videos.filter(video_type=selected_type)

    # Order by created date
    videos = videos.order_by('-created_at')

    # Pagination
    paginator = Paginator(videos, 10)  # Show 10 videos per page
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)

    # Get categories for filter
    categories = Category.objects.filter(is_active=True)

    context = {
        'videos': page_obj,
        'user_profile': user_profile,
        'categories': categories,
        'search_query': search_query,
        'selected_category': selected_category,
        'selected_type': selected_type,
        'page_obj': page_obj,
    }

    return render(request, 'videos/video_list.html', context)

@login_required
def add_video(request):
    # Get user profile
    user_profile = request.user.profile

    if request.method == 'POST':
        try:
            # Log the POST data
            logger.info(f"Received POST data: {request.POST}")
            logger.info(f"Received FILES: {request.FILES}")
            
            # Convert duration from minutes to seconds
            duration_minutes = int(request.POST['duration'])
            duration_seconds = duration_minutes * 60
            
            # Create video with processing fields properly initialized
            video = Video.objects.create(
                title=request.POST['title'],
                description=request.POST['description'],
                category_id=request.POST['category'],
                video_type=request.POST['video_type'],
                thumbnail=request.FILES.get('thumbnail'),
                portrait_thumbnail=request.FILES.get('portrait_thumbnail'),
                video_file=request.FILES.get('video_file'),
                promo_video=request.FILES.get('promo_video'),
                release_date=request.POST['release_date'],
                duration=duration_seconds,
                created_by=request.user,
                # Initialize processing fields
                is_processed=False,
                processing_status='processing',
                progress_percent=0,
                is_promo_processed=False,
                promo_processing_status='not_started',
                promo_progress_percent=0
            )

            # Log successful video creation
            logger.info(f"Successfully created video with ID: {video.id}")

            # Handle rental prices
            rental_durations = request.POST.getlist('rental_duration[]')
            rental_prices = request.POST.getlist('rental_price[]')
            for duration, price in zip(rental_durations, rental_prices):
                if duration and price:
                    VideoPrice.objects.create(
                        video=video,
                        rental_duration=int(duration),
                        rental_price=price,
                        is_active=True
                    )

            # Process videos synchronously
            processing_errors = []
            
            # Process main video first
            if video.video_file:
                try:
                    logger.info(f"Starting main video processing for video ID: {video.id}")
                    # Get fresh copy of video
                    video = Video.objects.get(id=video.id)
                    process_video_upload(video.id)
                    # Verify the update
                    video.refresh_from_db()
                    if not video.hls_url:
                        raise Exception("Main video HLS URL not updated after processing")
                    logger.info(f"Main video processing completed for video ID: {video.id}. HLS URL: {video.hls_url}")
                except Exception as e:
                    logger.error(f"Main video processing failed for video ID: {video.id}: {str(e)}", exc_info=True)
                    processing_errors.append(f"Main video: {str(e)}")
            
            # Process promo video if uploaded
            if video.promo_video:
                try:
                    logger.info(f"Starting promo video processing for video ID: {video.id}")
                    # Get fresh copy of video
                    video = Video.objects.get(id=video.id)
                    video.promo_processing_status = 'processing'
                    video.save()
                    process_promo_video(video.id)
                    # Verify the update
                    video.refresh_from_db()
                    if not video.promo_hls_url:
                        raise Exception("Promo video HLS URL not updated after processing")
                    logger.info(f"Promo video processing completed for video ID: {video.id}. HLS URL: {video.promo_hls_url}")
                except Exception as e:
                    logger.error(f"Promo video processing failed for video ID: {video.id}: {str(e)}", exc_info=True)
                    processing_errors.append(f"Promo video: {str(e)}")
            
            # Final verification
            video.refresh_from_db()
            logger.info(f"Final video state - Main HLS: {video.hls_url}, Promo HLS: {video.promo_hls_url}")
            
            # Handle processing results
            if not processing_errors:
                messages.success(request, 'Video added and processed successfully!')
            else:
                error_msg = "Video added but processing had errors: " + "; ".join(processing_errors)
                messages.warning(request, error_msg)
            
            return redirect('video_list')

        except Exception as e:
            logger.error(f"Error adding video: {str(e)}", exc_info=True)
            messages.error(request, f'Error adding video: {str(e)}')
            return redirect('add_video')

    # Get categories for form
    categories = Category.objects.filter(is_active=True)
    video_types = Video.VIDEO_TYPES

    return render(request, 'videos/video_form.html', {
        'user_profile': user_profile,
        'categories': categories,
        'video_types': video_types,
    })

@login_required
def edit_video(request, video_id):
    # Get user profile
    user_profile = request.user.profile
    video = get_object_or_404(Video, id=video_id)
    
    if request.method == 'POST':
        try:
            # Update video
            video.title = request.POST['title']
            video.description = request.POST['description']
            video.category_id = request.POST['category']
            video.video_type = request.POST['video_type']
            video.release_date = request.POST['release_date']
            video.duration = int(request.POST['duration'])

            if 'thumbnail' in request.FILES:
                video.thumbnail = request.FILES['thumbnail']
                
            if 'portrait_thumbnail' in request.FILES:
                video.portrait_thumbnail = request.FILES['portrait_thumbnail']
                
            if 'video_file' in request.FILES:
                video.video_file = request.FILES['video_file']
                video.is_processed = False
                video.processing_status = 'processing'
                video.hls_url = None
                
            if 'promo_video' in request.FILES:
                video.promo_video = request.FILES['promo_video']
                video.is_promo_processed = False
                video.promo_processing_status = 'processing'
                video.promo_hls_url = None

            video.save()

            # Update rental prices
            video.prices.all().delete()  # Remove existing prices
            rental_durations = request.POST.getlist('rental_duration')
            for duration in rental_durations:
                price = request.POST.get(f'rental_price_{duration}')
                if price:
                    VideoPrice.objects.create(
                        video=video,
                        rental_duration=int(duration),
                        rental_price=price,
                        is_active=True
                    )

            # Start processing in background if needed
            with ThreadPoolExecutor() as executor:
                if 'video_file' in request.FILES:
                    executor.submit(process_video_upload, video.id)
                if 'promo_video' in request.FILES:
                    executor.submit(process_promo_video, video.id)

            messages.success(request, 'Video updated successfully! New files will be processed in the background.')
            return redirect('video_list')

        except Exception as e:
            logger.error(f"Error updating video: {str(e)}")
            messages.error(request, f'Error updating video: {str(e)}')
            return redirect('edit_video', video_id=video_id)

    # Get categories for form
    categories = Category.objects.filter(is_active=True)
    video_types = Video.VIDEO_TYPES

    return render(request, 'videos/video_form.html', {
        'user_profile': user_profile,  # Add user_profile to context
        'video': video,
        'categories': categories,
        'video_types': video_types,
    })

@login_required
def toggle_video_status(request, video_id):
    video = get_object_or_404(Video, id=video_id)
    video.is_active = not video.is_active
    video.save()
    return JsonResponse({'status': 'success'})

@login_required
def delete_video(request, video_id):
    video = get_object_or_404(Video, id=video_id)
    video.delete()
    return JsonResponse({'status': 'success'})

@api_view(['GET'])
@permission_classes([AllowAny])
def get_videos_by_category(request, category_id):
    try:
        # Get page number from query params, default to 1
        page = request.GET.get('page', 1)
        page_size = request.GET.get('page_size', 10)
        
        # Get the category
        category = Category.objects.get(id=category_id, is_active=True)
        
        # Get active videos for this category
        videos = Video.objects.filter(
            category=category,
            is_active=True,
            is_processed=True,
            processing_status='completed'
        ).order_by('-created_at')
        
        # Setup pagination
        paginator = Paginator(videos, page_size)
        try:
            videos_page = paginator.page(page)
        except PageNotAnInteger:
            videos_page = paginator.page(1)
        except EmptyPage:
            videos_page = paginator.page(paginator.num_pages)
        
        # Serialize the videos
        video_data = []
        for video in videos_page:
            video_data.append({
                'id': video.id,
                'title': video.title,
                'description': video.description,
                'thumbnail_url': video.thumbnail_url,
                'portrait_thumbnail_url': video.portrait_thumbnail_url,  # Added portrait thumbnail
                'video_url': video.video_url,
                'promo_video_url': video.promo_video_url,  # Added promo video URL
                'promo_hls_url': video.promo_hls_url,  # Added promo HLS URL
                'duration': video.duration,
                'views_count': video.views_count,
                'created_at': video.created_at,
                'video_type': video.video_type,
                'is_premium': video.video_type in ['paid', 'rental']
            })
        
        response_data = {
            'status': 'success',
            'message': f'Videos for category: {category.name}',
            'category': {
                'id': category.id,
                'name': category.name,
                'description': category.description
            },
            'data': video_data,
            'pagination': {
                'current_page': videos_page.number,
                'total_pages': paginator.num_pages,
                'total_items': paginator.count,
                'has_next': videos_page.has_next(),
                'has_previous': videos_page.has_previous()
            }
        }
        
        return Response(response_data, status=status.HTTP_200_OK)
        
    except Category.DoesNotExist:
        return Response({
            'status': 'error',
            'message': 'Category not found'
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([AllowAny])
def get_hero_videos(request):
    """Get hero videos for frontend display"""
    try:
        hero_videos = Video.objects.filter(
            is_hero=True,
            is_active=True,
            processing_status='completed'
        ).order_by('-hero_order')[:5]
        
        serializer = VideoSerializer(hero_videos, many=True, context={'request': request})
        
        response = Response({
            'status': 'success',
            'data': serializer.data
        })
        
        # Add CORS headers
        response["Access-Control-Allow-Origin"] = "*"
        response["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        response["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        
        return response
    except Exception as e:
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=500)

@login_required
def hero_management(request):
    """View for managing hero videos"""
    hero_videos = Video.objects.filter(is_hero=True).order_by('-hero_order')
    available_videos = Video.objects.filter(
        is_hero=False,
        is_active=True,
        processing_status='completed'
    ).order_by('-created_at')

    context = {
        'hero_videos': hero_videos,
        'available_videos': available_videos
    }
    return render(request, 'videos/hero_management.html', context)

@login_required
@require_http_methods(["POST"])
def toggle_hero_status(request, video_id):
    """Toggle hero status for a video"""
    try:
        video = Video.objects.get(id=video_id)
        data = json.loads(request.body)
        is_hero = data.get('is_hero', False)

        # Check if maximum hero videos limit is reached
        if is_hero and Video.objects.filter(is_hero=True).count() >= 5:
            return JsonResponse({
                'status': 'error',
                'message': 'Maximum 5 videos can be selected for hero section'
            }, status=400)

        video.is_hero = is_hero
        if is_hero:
            # Set the order to be last
            max_order = Video.objects.filter(is_hero=True).aggregate(Max('hero_order'))['hero_order__max'] or 0
            video.hero_order = max_order + 1
        else:
            video.hero_order = 0
        video.save()

        return JsonResponse({
            'status': 'success',
            'message': 'Hero status updated successfully'
        })
    except Video.DoesNotExist:
        return JsonResponse({
            'status': 'error',
            'message': 'Video not found'
        }, status=404)
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)

@login_required
@require_http_methods(["POST"])
def update_hero_order(request):
    """Update the order of hero videos"""
    try:
        data = json.loads(request.body)
        order_data = data.get('order', [])

        with transaction.atomic():
            for item in order_data:
                video_id = item['id']
                order = item['order']
                Video.objects.filter(id=video_id).update(hero_order=order)

        return JsonResponse({
            'status': 'success',
            'message': 'Order updated successfully'
        })
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)
