from django.db import models
from django.contrib.auth.models import User
from django.utils.text import slugify

# Create your models here.

class UserRole(models.Model):
    ROLE_CHOICES = [
        ('super_admin', 'Super Admin'),
        ('manager', 'Manager'),
        ('editor', 'Editor'),
    ]
    name = models.CharField(max_length=20, choices=ROLE_CHOICES, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.get_name_display()

    def get_name_display(self):
        return dict(self.ROLE_CHOICES)[self.name]

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    role = models.ForeignKey(UserRole, on_delete=models.PROTECT)
    phone = models.CharField(max_length=15, blank=True, null=True)
    address = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    is_online = models.BooleanField(default=False)
    last_activity = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.email} - {self.role.get_name_display()}"

class LoginHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='login_history')
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    class Meta:
        verbose_name_plural = 'Login Histories'
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.user.username} - {self.timestamp}"

class BugReport(models.Model):
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('resolved', 'Resolved'),
        ('closed', 'Closed'),
    ]
    
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    TYPE_CHOICES = [
        ('functional', 'Functional Issue'),
        ('ui', 'UI/UX Issue'),
        ('performance', 'Performance Issue'),
        ('security', 'Security Concern'),
        ('other', 'Other'),
    ]

    title = models.CharField(max_length=200)
    description = models.TextField()
    bug_type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    steps_to_reproduce = models.TextField()
    expected_behavior = models.TextField()
    actual_behavior = models.TextField()
    browser = models.CharField(max_length=100)
    operating_system = models.CharField(max_length=100)
    additional_info = models.TextField(blank=True, null=True)
    reporter = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reported_bugs')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_bugs')

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.title} ({self.get_severity_display()})"

    def get_status_badge_class(self):
        status_classes = {
            'open': 'bg-blue-100 text-blue-800',
            'in_progress': 'bg-yellow-100 text-yellow-800',
            'resolved': 'bg-green-100 text-green-800',
            'closed': 'bg-gray-100 text-gray-800',
        }
        return status_classes.get(self.status, 'bg-gray-100 text-gray-800')

    def get_severity_badge_class(self):
        severity_classes = {
            'low': 'bg-green-100 text-green-800',
            'medium': 'bg-yellow-100 text-yellow-800',
            'high': 'bg-orange-100 text-orange-800',
            'critical': 'bg-red-100 text-red-800',
        }
        return severity_classes.get(self.severity, 'bg-gray-100 text-gray-800')

class BugReportReply(models.Model):
    bug_report = models.ForeignKey(BugReport, on_delete=models.CASCADE, related_name='replies')
    admin = models.ForeignKey(User, on_delete=models.CASCADE, related_name='bug_replies')
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Reply to {self.bug_report.title} by {self.admin.username}"

class Category(models.Model):
    name = models.CharField(max_length=100)
    slug = models.SlugField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    image = models.ImageField(upload_to='categories/', null=True, blank=True)
    icon = models.CharField(max_length=50, blank=True, help_text="Font Awesome icon class")
    parent = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='subcategories')
    order = models.IntegerField(default=0)
    is_active = models.BooleanField(default=True)
    home = models.BooleanField(default=False, help_text="Show this category on home page")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_categories')
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='updated_categories')

    class Meta:
        verbose_name_plural = "Categories"
        ordering = ['order', 'name']

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
        super().save(*args, **kwargs)

    def get_subcategories(self):
        return self.subcategories.filter(is_active=True)

    def get_full_path(self):
        if self.parent:
            return f"{self.parent.name} > {self.name}"
        return self.name

class LiveStream(models.Model):
    title = models.CharField(max_length=200)
    live_url = models.URLField()
    category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name='live_streams')
    thumbnail = models.ImageField(upload_to='live_streams/thumbnails/', null=True, blank=True)
    is_important = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    order = models.PositiveIntegerField(default=0, blank=False, null=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_live_streams')
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='updated_live_streams')

    class Meta:
        ordering = ['order', '-created_at']

    def __str__(self):
        return self.title

class State(models.Model):
    name = models.CharField(max_length=100)
    image = models.ImageField(upload_to='states/', null=True, blank=True)
    is_active = models.BooleanField(default=True)
    order = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_states')
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='updated_states')

    def __str__(self):
        return self.name

    class Meta:
        ordering = ['order', 'name']

class District(models.Model):
    state = models.ForeignKey(State, on_delete=models.CASCADE, related_name='districts')
    name = models.CharField(max_length=100)
    image = models.ImageField(upload_to='districts/', null=True, blank=True)
    is_active = models.BooleanField(default=True)
    order = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_districts')
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='updated_districts')

    def __str__(self):
        return f"{self.name}, {self.state.name}"

    class Meta:
        ordering = ['state', 'order', 'name']

class Constituency(models.Model):
    district = models.ForeignKey(District, on_delete=models.CASCADE, related_name='constituencies')
    name = models.CharField(max_length=100)
    image = models.ImageField(upload_to='constituencies/', null=True, blank=True)
    is_active = models.BooleanField(default=True)
    order = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_constituencies')
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='updated_constituencies')

    def __str__(self):
        return f"{self.name}, {self.district.name}"

    class Meta:
        ordering = ['district', 'order', 'name']
        verbose_name_plural = 'constituencies'

class Mandal(models.Model):
    constituency = models.ForeignKey(Constituency, on_delete=models.CASCADE, related_name='mandals')
    name = models.CharField(max_length=100)
    image = models.ImageField(upload_to='mandals/', null=True, blank=True)
    is_active = models.BooleanField(default=True)
    order = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_mandals')
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='updated_mandals')

    def __str__(self):
        return f"{self.name}, {self.constituency.name}"

    class Meta:
        ordering = ['constituency', 'order', 'name']

class Village(models.Model):
    mandal = models.ForeignKey(Mandal, on_delete=models.CASCADE, related_name='villages')
    name = models.CharField(max_length=100)
    image = models.ImageField(upload_to='villages/', null=True, blank=True)
    is_active = models.BooleanField(default=True)
    order = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_villages')
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='updated_villages')

    def __str__(self):
        return f"{self.name}, {self.mandal.name}"

    class Meta:
        ordering = ['mandal', 'order', 'name']

class RegionalVideo(models.Model):
    CATEGORY_CHOICES = [
        ('news', 'News'),
        ('culture', 'Culture & Festivals'),
        ('education', 'Education'),
        ('agriculture', 'Agriculture'),
        ('development', 'Development'),
        ('other', 'Other')
    ]

    title = models.CharField(max_length=200)
    description = models.TextField()
    video_url = models.URLField()
    thumbnail = models.ImageField(upload_to='regional_videos/thumbnails/')
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES)
    
    # Location references
    state = models.ForeignKey(State, on_delete=models.CASCADE, related_name='videos')
    district = models.ForeignKey(District, on_delete=models.CASCADE, related_name='videos')
    constituency = models.ForeignKey(Constituency, on_delete=models.CASCADE, related_name='videos', null=True, blank=True)
    mandal = models.ForeignKey(Mandal, on_delete=models.CASCADE, related_name='videos', null=True, blank=True)
    village = models.ForeignKey(Village, on_delete=models.CASCADE, related_name='videos', null=True, blank=True)
    
    # Video properties
    duration = models.DurationField()
    is_premium = models.BooleanField(default=False)
    is_hd = models.BooleanField(default=False)
    is_trending = models.BooleanField(default=False)
    views_count = models.IntegerField(default=0)
    
    # Status and ordering
    is_active = models.BooleanField(default=True)
    order = models.IntegerField(default=0)
    
    # Timestamps and user tracking
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_regional_videos')
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='updated_regional_videos')

    def __str__(self):
        return self.title

    class Meta:
        ordering = ['-created_at']

class Video(models.Model):
    VIDEO_TYPES = [
        ('free', 'Free'),
        ('paid', 'Paid'),
        ('rental', 'Rental'),
    ]

    title = models.CharField(max_length=255)
    description = models.TextField()
    thumbnail = models.ImageField(upload_to='videos/thumbnails/')
    portrait_thumbnail = models.ImageField(
        upload_to='videos/portrait_thumbnails/',
        null=True,
        blank=True,
        help_text='Portrait thumbnail (9:16 ratio) for mobile view'
    )
    video_file = models.FileField(upload_to='videos/files/')
    promo_video = models.FileField(
        upload_to='videos/promos/',
        null=True,
        blank=True,
        help_text='Short promotional video clip'
    )
    promo_hls_url = models.URLField(
        max_length=500, 
        null=True, 
        blank=True, 
        help_text='URL to master HLS playlist for promo video'
    )
    is_promo_processed = models.BooleanField(
        default=False,
        help_text='Whether promo video has been converted to HLS'
    )
    promo_processing_status = models.CharField(
        max_length=20,
        default='pending',
        choices=[
            ('pending', 'Pending'),
            ('processing', 'Processing'),
            ('completed', 'Completed'),
            ('failed', 'Failed')
        ],
        help_text='Processing status of promo video'
    )
    promo_processing_error = models.TextField(
        null=True,
        blank=True,
        help_text='Error message if promo video processing failed'
    )
    promo_progress_percent = models.FloatField(
        default=0,
        help_text='Progress percentage of promo video processing'
    )
    hls_url = models.URLField(max_length=500, null=True, blank=True, help_text='URL to master HLS playlist')
    category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name='videos')
    video_type = models.CharField(max_length=10, choices=VIDEO_TYPES)
    duration = models.IntegerField(help_text='Duration in seconds')
    release_date = models.DateField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='videos_created')
    views_count = models.IntegerField(default=0)
    is_processed = models.BooleanField(default=False, help_text='Whether video has been converted to HLS')
    processing_status = models.CharField(max_length=20, default='pending', choices=[
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed')
    ])
    processing_error = models.TextField(null=True, blank=True)
    progress_percent = models.FloatField(default=0, help_text='Progress percentage of video processing')
    is_hero = models.BooleanField(default=False, help_text="Select to display this video in hero section")
    hero_order = models.IntegerField(default=0, help_text="Order in which to display hero videos (0 = last)")

    def __str__(self):
        return self.title

    @property
    def thumbnail_url(self):
        if self.thumbnail:
            return self.thumbnail.url
        return None

    @property
    def portrait_thumbnail_url(self):
        if self.portrait_thumbnail:
            return self.portrait_thumbnail.url
        return self.thumbnail_url  # Fallback to regular thumbnail if portrait not available

    @property
    def promo_video_url(self):
        if self.is_promo_processed and self.promo_hls_url:
            return self.promo_hls_url
        elif self.promo_video:
            return self.promo_video.url
        return None

    @property
    def video_url(self):
        if self.is_processed and self.hls_url:
            return self.hls_url
        elif self.video_file:
            return self.video_file.url
        return None

    class Meta:
        ordering = ['-hero_order', '-created_at']

class VideoPrice(models.Model):
    RENTAL_DURATIONS = [
        (24, '24 Hours'),
        (48, '48 Hours'),
        (72, '72 Hours'),
    ]

    video = models.ForeignKey(Video, on_delete=models.CASCADE, related_name='prices')
    rental_duration = models.IntegerField(choices=RENTAL_DURATIONS, null=True, blank=True)
    rental_price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    subscription_tier = models.CharField(max_length=50, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('video', 'rental_duration')

    def __str__(self):
        if self.rental_duration:
            return f"{self.video.title} - {self.rental_duration}hrs rental"
        return f"{self.video.title} - {self.subscription_tier} tier"

class UserVideo(models.Model):
    PURCHASE_TYPES = [
        ('rental', 'Rental'),
        ('subscription', 'Subscription'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='purchased_videos')
    video = models.ForeignKey(Video, on_delete=models.CASCADE, related_name='purchases')
    purchase_type = models.CharField(max_length=20, choices=PURCHASE_TYPES)
    purchase_date = models.DateTimeField(auto_now_add=True)
    expiry_date = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    amount_paid = models.DecimalField(max_digits=10, decimal_places=2)

    class Meta:
        unique_together = ('user', 'video', 'purchase_date')

    def __str__(self):
        return f"{self.user.username} - {self.video.title}"

class Cast(models.Model):
    name = models.CharField(max_length=255)
    role = models.CharField(max_length=100)
    image = models.ImageField(upload_to='cast/images/', null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    @property
    def image_url(self):
        if self.image:
            return self.image.url
        return None

class VideoCast(models.Model):
    video = models.ForeignKey(Video, on_delete=models.CASCADE, related_name='video_cast')
    cast = models.ForeignKey(Cast, on_delete=models.CASCADE)
    order = models.IntegerField(default=0)  # For ordering cast members
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['order']
        unique_together = ('video', 'cast')

    def __str__(self):
        return f"{self.video.title} - {self.cast.name}"
