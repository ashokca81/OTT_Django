from rest_framework import serializers
from .models import LiveStream, Category, State, District, Constituency, Mandal, Village, RegionalVideo, Video, VideoPrice, UserVideo, Cast, VideoCast, WatchList

class CategorySerializer(serializers.ModelSerializer):
    image_url = serializers.SerializerMethodField()

    class Meta:
        model = Category
        fields = ['id', 'name', 'slug', 'description', 'image', 'image_url', 'icon', 'parent', 'order', 'is_active', 'created_at', 'updated_at']
        read_only_fields = ['created_at', 'updated_at', 'slug']

    def get_image_url(self, obj):
        if obj.image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.image.url)
        return None

class LiveStreamSerializer(serializers.ModelSerializer):
    category_name = serializers.CharField(source='category.name', read_only=True)
    
    class Meta:
        model = LiveStream
        fields = ['id', 'title', 'live_url', 'category', 'category_name', 'thumbnail', 'is_important', 'is_active', 'created_at', 'updated_at']
        read_only_fields = ['created_at', 'updated_at']

class StateSerializer(serializers.ModelSerializer):
    districts_count = serializers.SerializerMethodField()

    class Meta:
        model = State
        fields = ['id', 'name', 'image', 'is_active', 'order', 'districts_count']

    def get_districts_count(self, obj):
        return obj.districts.filter(is_active=True).count()

class DistrictSerializer(serializers.ModelSerializer):
    class Meta:
        model = District
        fields = ['id', 'state', 'name', 'image', 'is_active', 'order']

class ConstituencySerializer(serializers.ModelSerializer):
    image_url = serializers.SerializerMethodField()
    mandals_count = serializers.SerializerMethodField()

    class Meta:
        model = Constituency
        fields = ['id', 'district', 'name', 'image', 'image_url', 'is_active', 'order', 'mandals_count']

    def get_image_url(self, obj):
        if obj.image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.image.url)
        return None

    def get_mandals_count(self, obj):
        return obj.mandals.filter(is_active=True).count()

class MandalSerializer(serializers.ModelSerializer):
    class Meta:
        model = Mandal
        fields = ['id', 'constituency', 'name', 'image', 'is_active', 'order']

class VillageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Village
        fields = ['id', 'mandal', 'name', 'image', 'is_active', 'order']

class RegionalVideoSerializer(serializers.ModelSerializer):
    state_name = serializers.CharField(source='state.name', read_only=True)
    district_name = serializers.CharField(source='district.name', read_only=True)
    constituency_name = serializers.CharField(source='constituency.name', read_only=True)
    mandal_name = serializers.CharField(source='mandal.name', read_only=True)
    village_name = serializers.CharField(source='village.name', read_only=True)
    
    class Meta:
        model = RegionalVideo
        fields = [
            'id', 'title', 'description', 'video_url', 'thumbnail', 'category',
            'state', 'state_name', 'district', 'district_name',
            'constituency', 'constituency_name', 'mandal', 'mandal_name',
            'village', 'village_name', 'duration', 'is_premium', 'is_hd',
            'is_trending', 'views_count', 'is_active', 'order', 'created_at'
        ]

class DetailedStateSerializer(serializers.ModelSerializer):
    districts = DistrictSerializer(many=True, read_only=True)
    videos_count = serializers.SerializerMethodField()
    districts_count = serializers.SerializerMethodField()

    class Meta:
        model = State
        fields = ['id', 'name', 'image', 'is_active', 'order', 'districts', 'districts_count', 'videos_count']
    
    def get_videos_count(self, obj):
        return obj.videos.filter(is_active=True).count()

    def get_districts_count(self, obj):
        return obj.districts.filter(is_active=True).count()

class DetailedDistrictSerializer(serializers.ModelSerializer):
    constituencies = ConstituencySerializer(many=True, read_only=True)
    videos_count = serializers.SerializerMethodField()
    state_name = serializers.CharField(source='state.name', read_only=True)
    image_url = serializers.SerializerMethodField()
    constituencies_count = serializers.SerializerMethodField()

    class Meta:
        model = District
        fields = ['id', 'name', 'image', 'image_url', 'is_active', 'order', 'state', 'state_name', 'constituencies', 'constituencies_count', 'videos_count']
    
    def get_videos_count(self, obj):
        return obj.videos.filter(is_active=True).count()

    def get_image_url(self, obj):
        if obj.image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.image.url)
        return None

    def get_constituencies_count(self, obj):
        return obj.constituencies.filter(is_active=True).count()

class DetailedConstituencySerializer(serializers.ModelSerializer):
    mandals = MandalSerializer(many=True, read_only=True)
    videos_count = serializers.SerializerMethodField()
    district_name = serializers.CharField(source='district.name', read_only=True)
    state_name = serializers.CharField(source='district.state.name', read_only=True)

    class Meta:
        model = Constituency
        fields = ['id', 'name', 'image', 'is_active', 'order', 'district', 'district_name', 'state_name', 'mandals', 'videos_count']
    
    def get_videos_count(self, obj):
        return obj.videos.filter(is_active=True).count()

class DetailedMandalSerializer(serializers.ModelSerializer):
    villages = VillageSerializer(many=True, read_only=True)
    videos_count = serializers.SerializerMethodField()
    constituency_name = serializers.CharField(source='constituency.name', read_only=True)
    district_name = serializers.CharField(source='constituency.district.name', read_only=True)
    state_name = serializers.CharField(source='constituency.district.state.name', read_only=True)

    class Meta:
        model = Mandal
        fields = ['id', 'name', 'image', 'is_active', 'order', 'constituency', 'constituency_name', 
                 'district_name', 'state_name', 'villages', 'videos_count']
    
    def get_videos_count(self, obj):
        return obj.videos.filter(is_active=True).count()

class DetailedVillageSerializer(serializers.ModelSerializer):
    videos = RegionalVideoSerializer(many=True, read_only=True)
    videos_count = serializers.SerializerMethodField()
    mandal_name = serializers.CharField(source='mandal.name', read_only=True)
    constituency_name = serializers.CharField(source='mandal.constituency.name', read_only=True)
    district_name = serializers.CharField(source='mandal.constituency.district.name', read_only=True)
    state_name = serializers.CharField(source='mandal.constituency.district.state.name', read_only=True)

    class Meta:
        model = Village
        fields = ['id', 'name', 'image', 'is_active', 'order', 'mandal', 'mandal_name',
                 'constituency_name', 'district_name', 'state_name', 'videos', 'videos_count']
    
    def get_videos_count(self, obj):
        return obj.videos.filter(is_active=True).count()

class VideoPriceSerializer(serializers.ModelSerializer):
    class Meta:
        model = VideoPrice
        fields = ['id', 'rental_duration', 'rental_price', 'subscription_tier', 'is_active']

class CastSerializer(serializers.ModelSerializer):
    image_url = serializers.SerializerMethodField()

    class Meta:
        model = Cast
        fields = ['id', 'name', 'role', 'image_url']

    def get_image_url(self, obj):
        if obj.image:
            return obj.image.url
        return None

class VideoCastSerializer(serializers.ModelSerializer):
    cast = CastSerializer(read_only=True)

    class Meta:
        model = VideoCast
        fields = ['cast', 'order']

class VideoSerializer(serializers.ModelSerializer):
    category_name = serializers.CharField(source='category.name', read_only=True)
    prices = VideoPriceSerializer(many=True, read_only=True)
    thumbnail_url = serializers.SerializerMethodField()
    promo_hls_url = serializers.SerializerMethodField()
    hls_url = serializers.SerializerMethodField()
    cast = serializers.SerializerMethodField()

    class Meta:
        model = Video
        fields = ['id', 'title', 'description', 'thumbnail_url',
                  'promo_hls_url', 'hls_url', 'category', 'category_name', 'video_type', 'duration',
                 'release_date', 'is_active', 'views_count', 'prices', 'cast']
        read_only_fields = ['views_count', 'created_by']

    def get_thumbnail_url(self, obj):
        if obj.thumbnail:
            return obj.thumbnail.url
        return None

    def get_promo_hls_url(self, obj):
        if obj.is_promo_processed and obj.promo_hls_url:
            return obj.promo_hls_url
        return None

    def get_hls_url(self, obj):
        # Check if we should exclude hls_url
        if self.context.get('exclude_hls_url'):
            return None
        if obj.is_processed and obj.hls_url:
            return obj.hls_url
        return None

    def get_cast(self, obj):
        video_cast = obj.video_cast.filter(is_active=True).order_by('order')
        return VideoCastSerializer(video_cast, many=True).data

    def to_representation(self, instance):
        data = super().to_representation(instance)
        
        # Add HLS URL if video is processed and not excluded
        if not self.context.get('exclude_hls_url'):
            if instance.is_processed and instance.hls_url:
                data['hls_url'] = instance.hls_url
            
        # Add promo HLS URL if promo is processed
        if instance.is_promo_processed and instance.promo_hls_url:
            data['promo_hls_url'] = instance.promo_hls_url
            
        return data

    def create(self, validated_data):
        validated_data['created_by'] = self.context['request'].user
        return super().create(validated_data)

class UserVideoSerializer(serializers.ModelSerializer):
    video_title = serializers.CharField(source='video.title', read_only=True)
    video_thumbnail = serializers.SerializerMethodField()

    class Meta:
        model = UserVideo
        fields = ['id', 'video', 'video_title', 'video_thumbnail', 'purchase_type',
                 'purchase_date', 'expiry_date', 'is_active', 'amount_paid']
        read_only_fields = ['purchase_date']

    def get_video_thumbnail(self, obj):
        request = self.context.get('request')
        if obj.video.thumbnail and request:
            return request.build_absolute_uri(obj.video.thumbnail.url)
        return None 

class WatchListSerializer(serializers.ModelSerializer):
    content_details = VideoSerializer(source='content', read_only=True)
    
    class Meta:
        model = WatchList
        fields = ['id', 'user', 'content', 'content_details', 'added_date']
        read_only_fields = ['user', 'added_date'] 