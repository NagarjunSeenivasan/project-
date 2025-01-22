import os
from pymongo import MongoClient
from celery import Celery
from flask import Flask

# Initialize the Flask app
app = Flask(__name__)

# Database URI and MongoClient
uri = os.getenv("MONGODB_URI", "mongodb+srv://cadibalinfo:Nevinotech512@cadibal.co2kz.mongodb.net/?retryWrites=true&w=majority&appName=CADIBAL")
client = MongoClient(uri)
db = client['CADIBAL']

# Mongo collections
users_collection = db['users']
videos_collection = db['videos']
jobs_collection = db['jobs']
posts_collection = db['posts']
notifications_collection = db['notifications']
ads_collection = db['ads']
messages_collection = db['messages']
admin_collection = db["admin_collection"]
timeline_collection = db["timeline"]

# File upload configurations
UPLOAD_FOLDER = '/var/www/html/cadibal-media/static/uploads'
UPLOAD_FOLDER_VIDEOS = '/var/www/html/cadibal-media/static/uploads/videos'
UPLOAD_FOLDER_THUMBNAILS = '/var/www/html/cadibal-media/static/uploads/thumbnails'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'avi', 'mov'}
ALLOWED_VIDEO_EXTENSIONS = {'mp4', 'mov', 'avi', 'mkv'}
ALLOWED_IMAGE_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}
ALLOWED_FILE_EXTENSIONS = {'jpg', 'jpeg', 'png', 'pdf'}

# Celery and Redis configurations
celery = Celery('tasks', broker=os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0'))
celery.conf.update(app.config)

# Ensure necessary folders exist with proper permissions
for folder in [UPLOAD_FOLDER, UPLOAD_FOLDER_VIDEOS, UPLOAD_FOLDER_THUMBNAILS]:
    if not os.path.exists(folder):
        try:
            os.makedirs(folder)
        except PermissionError:
            app.logger.error(f"Permission error: Could not create folder {folder}")
            raise

# Ensure to add further app configurations and routes here
