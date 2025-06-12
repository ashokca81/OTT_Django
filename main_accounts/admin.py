from django.contrib import admin
from .models import Category, LiveStream, UserRole, UserProfile, LoginHistory, BugReport, BugReportReply, Video
from django.db import models
from adminsortable2.admin import SortableAdminMixin

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'parent', 'order', 'is_active', 'home')
    list_filter = ('is_active', 'home', 'parent')
    search_fields = ('name', 'description')
    prepopulated_fields = {'slug': ('name',)}
    list_editable = ('order', 'is_active', 'home')

@admin.register(LiveStream)
class LiveStreamAdmin(SortableAdminMixin, admin.ModelAdmin):
    list_display = ('title', 'category', 'is_important', 'is_active')
    list_filter = ('category', 'is_important', 'is_active')
    search_fields = ('title',)
    list_editable = ('is_important', 'is_active')
    ordering = ['order']

@admin.register(Video)
class VideoAdmin(admin.ModelAdmin):
    list_display = ['title', 'category', 'video_type', 'is_hero', 'hero_order', 'created_at']
    list_filter = ['video_type', 'is_hero', 'category']
    search_fields = ['title', 'description']
    ordering = ['-hero_order', '-created_at']
    list_editable = ['is_hero', 'hero_order']

# Register other models if not already registered
admin.site.register(UserRole)
admin.site.register(UserProfile)
admin.site.register(LoginHistory)
admin.site.register(BugReport)
admin.site.register(BugReportReply)
