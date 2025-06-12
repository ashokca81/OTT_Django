from django.conf import settings
from storages.backends.s3boto3 import S3Boto3Storage
from django.core.files.storage import FileSystemStorage
import logging
import os

logger = logging.getLogger(__name__)

class StaticStorage(S3Boto3Storage):
    location = settings.STATIC_LOCATION
    file_overwrite = True
    bucket_name = settings.AWS_STORAGE_BUCKET_NAME
    custom_domain = settings.AWS_S3_CUSTOM_DOMAIN

class PublicMediaStorage(S3Boto3Storage):
    location = settings.PUBLIC_MEDIA_LOCATION
    file_overwrite = False
    bucket_name = settings.AWS_STORAGE_BUCKET_NAME
    custom_domain = settings.AWS_S3_CUSTOM_DOMAIN
    
    def get_available_name(self, name, max_length=None):
        """
        Returns a filename that's free on the target storage system.
        """
        logger.info(f"Getting available name for: {name}")
        return super().get_available_name(name, max_length=max_length)
    
    def _save(self, name, content):
        """
        Save and return the name of the file.
        """
        logger.info(f"Saving file: {name}")
        try:
            # Clean the file name to remove unwanted characters
            name = os.path.basename(name)
            name = name.replace(' ', '_')
            name = ''.join(char for char in name if char.isalnum() or char in ('_', '-', '.'))
            
            # Add the location prefix
            if self.location:
                name = os.path.join(self.location, name)
                
            logger.info(f"Cleaned file name: {name}")
            name = super()._save(name, content)
            logger.info(f"File saved successfully: {name}")
            return name
        except Exception as e:
            logger.error(f"Error saving file {name}: {str(e)}")
            raise 