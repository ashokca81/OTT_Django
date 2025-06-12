import os
import subprocess
import uuid
from django.conf import settings
import boto3
from botocore.exceptions import ClientError
import logging
import math
from concurrent.futures import ThreadPoolExecutor
import json
import tempfile
from django.apps import apps
from django.db import transaction

logger = logging.getLogger(__name__)

def get_video_duration(input_path):
    """Get video duration using FFprobe"""
    try:
        cmd = [
            'ffprobe',
            '-v', 'error',
            '-show_entries', 'format=duration',
            '-of', 'default=noprint_wrappers=1:nokey=1',
            input_path
        ]
        output = subprocess.check_output(cmd).decode().strip()
        return float(output)
    except Exception as e:
        logger.error(f"Error getting video duration: {str(e)}")
        return None

def convert_to_hls(input_path, output_dir):
    """
    Convert video to HLS format with multiple quality variants based on input video quality
    """
    try:
        # Generate unique identifier
        unique_id = str(uuid.uuid4())
        
        # Create output directories
        os.makedirs(output_dir, exist_ok=True)
        hls_dir = os.path.join(output_dir, 'hls')
        os.makedirs(hls_dir, exist_ok=True)

        # Get input video resolution using FFprobe
        cmd = [
            'ffprobe',
            '-v', 'error',
            '-select_streams', 'v:0',
            '-show_entries', 'stream=width,height,pix_fmt',
            '-of', 'json',
            input_path
        ]
        probe_output = json.loads(subprocess.check_output(cmd).decode())
        input_height = int(probe_output['streams'][0]['height'])
        pix_fmt = probe_output['streams'][0].get('pix_fmt', 'yuv420p')

        # Define all possible variants
        all_variants = [
            {'name': '120p', 'height': 120, 'width': 214, 'bitrate': '250k', 'maxrate': '267k', 'bufsize': '375k', 'audiorate': '64k'},
            {'name': '240p', 'height': 240, 'width': 426, 'bitrate': '400k', 'maxrate': '428k', 'bufsize': '600k', 'audiorate': '64k'},
            {'name': '360p', 'height': 360, 'width': 640, 'bitrate': '800k', 'maxrate': '856k', 'bufsize': '1200k', 'audiorate': '96k'},
            {'name': '480p', 'height': 480, 'width': 842, 'bitrate': '1400k', 'maxrate': '1498k', 'bufsize': '2100k', 'audiorate': '128k'},
            {'name': '720p', 'height': 720, 'width': 1280, 'bitrate': '2800k', 'maxrate': '2996k', 'bufsize': '4200k', 'audiorate': '128k'},
            {'name': '1080p', 'height': 1080, 'width': 1920, 'bitrate': '5000k', 'maxrate': '5350k', 'bufsize': '7500k', 'audiorate': '192k'},
            {'name': '1440p', 'height': 1440, 'width': 2560, 'bitrate': '8000k', 'maxrate': '8560k', 'bufsize': '12000k', 'audiorate': '192k'}
        ]

        # Select variants based on input video height
        selected_variants = [v for v in all_variants if v['height'] <= input_height]
        if not selected_variants:
            selected_variants = [all_variants[0]]  # Use lowest quality if input is very small

        # Create directories for selected variants
        variant_dirs = {}
        for variant in selected_variants:
            variant_dir = os.path.join(hls_dir, f"{unique_id}_{variant['name']}")
            os.makedirs(variant_dir, exist_ok=True)
            variant_dirs[variant['name']] = variant_dir

        # Calculate segment duration based on file size
        file_size = os.path.getsize(input_path)
        segment_duration = min(max(10, int(file_size / (1024 * 1024 * 100))), 30)

        # Create master playlist
        master_playlist_content = '#EXTM3U\n#EXT-X-VERSION:3\n'
        for variant in selected_variants:
            master_playlist_content += f'#EXT-X-STREAM-INF:BANDWIDTH={(int(variant["bitrate"][:-1]) * 1000)},RESOLUTION={variant["width"]}x{variant["height"]}\n'
            master_playlist_content += f'{unique_id}_{variant["name"]}/playlist.m3u8\n'

        master_playlist_path = os.path.join(hls_dir, 'master.m3u8')
        with open(master_playlist_path, 'w') as f:
            f.write(master_playlist_content)

        # Determine x264 profile based on input pixel format
        x264_profile = 'high422' if '422' in pix_fmt else 'high'
        
        # FFmpeg commands for each variant
        commands = []
        for variant in selected_variants:
            commands.append([
                'ffmpeg', '-y',
                '-i', input_path,
                '-vf', f'scale={variant["width"]}:{variant["height"]}',
                '-c:v', 'libx264',
                '-profile:v', x264_profile,  # Use appropriate profile
                '-preset', 'fast',           # Faster encoding
                '-tune', 'film',             # Optimize for film content
                '-pix_fmt', 'yuv420p',       # Force yuv420p output
                '-crf', '23',                # Better quality
                '-sc_threshold', '0',
                '-g', '48',
                '-keyint_min', '48',
                '-hls_time', str(segment_duration),
                '-hls_list_size', '0',
                '-b:v', variant['bitrate'],
                '-maxrate', variant['maxrate'],
                '-bufsize', variant['bufsize'],
                '-b:a', variant['audiorate'],
                '-ar', '48000',
                '-ac', '2',
                '-f', 'hls',
                '-hls_segment_filename', f'{variant_dirs[variant["name"]]}/segment_%03d.ts',
                f'{variant_dirs[variant["name"]]}/playlist.m3u8'
            ])

        # Execute FFmpeg commands sequentially
        for cmd in commands:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                logger.error(f"FFmpeg stderr: {stderr.decode()}")
                raise Exception(f"FFmpeg conversion failed with return code {process.returncode}")

        return {
            'success': True,
            'output_dir': output_dir,
            'master_playlist': master_playlist_path,
            'unique_id': unique_id,
            'segment_duration': segment_duration,
            'variants': [v['name'] for v in selected_variants],
            'profile_used': x264_profile
        }
        
    except Exception as e:
        logger.error(f"Error in convert_to_hls: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }

def upload_to_s3(file_path, s3_key):
    """
    Upload a file to AWS S3
    """
    try:
        s3_client = boto3.client('s3',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_S3_REGION_NAME
        )
        
        # Set content type based on file extension
        content_type = 'application/octet-stream'  # default
        if file_path.endswith('.m3u8'):
            content_type = 'application/vnd.apple.mpegurl'
        elif file_path.endswith('.ts'):
            content_type = 'video/MP2T'
        
        # Upload with proper content type but without ACL
        s3_client.upload_file(
            file_path,
            settings.AWS_STORAGE_BUCKET_NAME,
            s3_key,
            ExtraArgs={
                'ContentType': content_type,
                'CacheControl': 'max-age=3600'
            }
        )
        
        # Generate S3 URL
        url = f"https://{settings.AWS_STORAGE_BUCKET_NAME}.s3.{settings.AWS_S3_REGION_NAME}.amazonaws.com/{s3_key}"
        return {'success': True, 'url': url}
        
    except ClientError as e:
        logger.error(f"S3 upload failed: {str(e)}")
        return {'success': False, 'error': str(e)}
    except Exception as e:
        logger.error(f"Error in upload_to_s3: {str(e)}")
        return {'success': False, 'error': str(e)}

def upload_hls_to_s3(hls_dir, video_id):
    """
    Upload all HLS files to S3
    """
    try:
        logger.info(f"Starting S3 upload for video ID: {video_id}")
        logger.info(f"HLS directory: {hls_dir}")
        
        base_s3_path = f'videos/hls/{video_id}'
        uploaded_files = []
        
        # Walk through the HLS directory
        for root, dirs, files in os.walk(hls_dir):
            logger.info(f"Processing directory: {root}")
            logger.info(f"Found files: {files}")
            
            for file in files:
                if file.endswith('.m3u8') or file.endswith('.ts'):
                    local_path = os.path.join(root, file)
                    relative_path = os.path.relpath(local_path, hls_dir)
                    s3_key = f"{base_s3_path}/{relative_path}"
                    
                    logger.info(f"Uploading file: {local_path} to S3 key: {s3_key}")
                    
                    # Upload file
                    result = upload_to_s3(local_path, s3_key)
                    if result['success']:
                        uploaded_files.append(result['url'])
                        logger.info(f"Successfully uploaded {s3_key}")
                    else:
                        logger.error(f"Failed to upload {s3_key}: {result.get('error')}")
                        return result
        
        # Get master playlist URL
        master_playlist_url = next(
            (url for url in uploaded_files if url.endswith('master.m3u8')),
            None
        )
        
        if not master_playlist_url:
            error_msg = "Master playlist URL not found in uploaded files"
            logger.error(error_msg)
            return {'success': False, 'error': error_msg}
            
        logger.info(f"Upload complete. Master playlist URL: {master_playlist_url}")
        logger.info(f"Total files uploaded: {len(uploaded_files)}")
        
        return {
            'success': True,
            'master_playlist_url': master_playlist_url,
            'all_urls': uploaded_files
        }
        
    except Exception as e:
        error_msg = f"Error in upload_hls_to_s3: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return {'success': False, 'error': error_msg}

def process_promo_video(video_id):
    """
    Process promo video upload and convert to HLS format with same qualities as main video
    """
    Video = apps.get_model('main_accounts', 'Video')
    video = Video.objects.get(id=video_id)
    
    try:
        # Create temporary directory for HLS conversion
        with tempfile.TemporaryDirectory() as temp_dir:
            # Download promo video file to temp directory
            input_path = os.path.join(temp_dir, 'promo_input.mp4')
            with open(input_path, 'wb') as f:
                f.write(video.promo_video.read())
            
            # Convert to HLS using same function as main video
            hls_result = convert_to_hls(input_path, os.path.join(temp_dir, 'hls'))
            
            if hls_result['success']:
                # Upload HLS files to S3 with promo prefix
                upload_result = upload_hls_to_s3(
                    os.path.join(temp_dir, 'hls'),
                    f"promo_{video.id}"  # Add promo prefix to differentiate from main video
                )
                
                if upload_result['success']:
                    # Update video model with promo HLS URL
                    video.promo_hls_url = upload_result['master_playlist_url']
                    video.is_promo_processed = True
                    video.promo_processing_status = 'completed'
                    video.save()
                else:
                    raise Exception(upload_result['error'])
            else:
                raise Exception(hls_result['error'])
                
    except Exception as e:
        logger.error(f"Error processing promo video {video_id}: {str(e)}")
        video.promo_processing_status = 'failed'
        video.promo_processing_error = str(e)
        video.save()

def process_video_upload(video_id):
    """
    Process video upload and convert to HLS format
    """
    Video = apps.get_model('main_accounts', 'Video')
    
    try:
        logger.info(f"Starting video processing for video ID: {video_id}")
        
        # Get video object - simple get, no transaction
        video = Video.objects.get(id=video_id)
        
        if not video.video_file:
            raise Exception("No video file found")
            
        # Create temporary directory for HLS conversion
        with tempfile.TemporaryDirectory() as temp_dir:
            # Download video file to temp directory
            input_path = os.path.join(temp_dir, 'input.mp4')
            logger.info(f"Downloading video file to {input_path}")
            
            try:
                with open(input_path, 'wb') as f:
                    video_content = video.video_file.read()
                    if not video_content:
                        raise Exception("Video file is empty")
                    f.write(video_content)
                
                # Check if file exists and has size
                if not os.path.exists(input_path) or os.path.getsize(input_path) == 0:
                    raise Exception("Failed to write video file or file is empty")
                    
                logger.info(f"Video file downloaded successfully. Size: {os.path.getsize(input_path)} bytes")
            except Exception as e:
                logger.error(f"Error downloading video file: {str(e)}", exc_info=True)
                raise Exception(f"Error downloading video file: {str(e)}")
            
            logger.info("Starting HLS conversion")
            # Convert to HLS
            hls_result = convert_to_hls(input_path, os.path.join(temp_dir, 'hls'))
            logger.info(f"HLS conversion result: {hls_result}")
            
            if hls_result['success']:
                logger.info("HLS conversion successful, uploading to S3")
                # Upload HLS files to S3
                upload_result = upload_hls_to_s3(
                    os.path.join(temp_dir, 'hls'),
                    video.id
                )
                logger.info(f"S3 upload result: {upload_result}")
                
                if upload_result['success'] and upload_result.get('master_playlist_url'):
                    logger.info(f"S3 upload successful. Master playlist URL: {upload_result['master_playlist_url']}")
                    
                    # Simple direct database update, like promo video
                    video.hls_url = upload_result['master_playlist_url']
                    video.is_processed = True
                    video.processing_status = 'completed'
                    video.processing_error = None
                    video.save()
                    
                    # Verify the update
                    video.refresh_from_db()
                    logger.info(f"Video state after update - hls_url: {video.hls_url}, processing_status: {video.processing_status}")
                    
                    if not video.hls_url:
                        raise Exception("Failed to update video HLS URL in database")
                        
                    logger.info(f"Video {video_id} processing completed successfully")
                else:
                    raise Exception(f"S3 upload failed or missing master playlist URL: {upload_result.get('error', 'Unknown error')}")
            else:
                raise Exception(f"HLS conversion failed: {hls_result.get('error', 'Unknown error')}")
                
    except Exception as e:
        logger.error(f"Error processing video {video_id}: {str(e)}", exc_info=True)
        try:
            video = Video.objects.get(id=video_id)
            video.processing_status = 'failed'
            video.processing_error = str(e)
            video.save()
            logger.info(f"Updated video {video_id} status to failed with error: {str(e)}")
        except Exception as db_error:
            logger.error(f"Failed to update error status in database: {str(db_error)}", exc_info=True)
        raise  # Re-raise the exception for the view to handle 