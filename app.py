from ctypes import cast
import os
import uuid
from werkzeug.utils import secure_filename
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
import bcrypt
from flask import render_template,Flask, request, redirect, url_for, flash, session,render_template,jsonify
from werkzeug.security import check_password_hash
import random
import string
from bson import ObjectId
from datetime import datetime
import pytz
from flask_socketio import SocketIO, emit, join_room
import logging
from datetime import datetime, timedelta
from celery import Celery
from dotenv import load_dotenv
import sys
import html
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from redis import Redis
from werkzeug.security import generate_password_hash
import datetime  # Ensure this is properly imported
from datetime import datetime
from urllib.parse import quote,unquote


# User input that may contain special characters
user_input = "<script>alert('XSS')</script>"

# Escape special characters
escaped_input = html.escape(user_input)

# Now, escaped_input will be: '&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;'

sys.stderr = sys.stdout
sys.path.insert(0, '/var/www/html/cadibal-media')

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_fallback_key')


# Logging setup
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


# Celery setup
celery = Celery('tasks', broker=os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0'))

# SocketIO setup
socketio = SocketIO(app, message_queue=os.getenv('SOCKETIO_MESSAGE_QUEUE', 'redis://'))


UPLOAD_FOLDER = '/var/www/html/cadibal-media/static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif','mp4', 'avi', 'mov'}
# Define the upload folder for posts
app.config['UPLOAD_FOLDER_POSTS'] = os.path.join(app.root_path, 'static', 'uploads')
app.config['CELERY_BROKER_URL'] = 'redis://localhost:6379/0'  # Redis as broker
celery = Celery(app.name, broker=app.config['CELERY_BROKER_URL'])
celery.conf.update(app.config)
upload_folder = os.path.join(os.getcwd(), 'static')

app.config['STATIC_FOLDER'] = os.path.join(os.getcwd(), 'static')
upload_folder = os.path.join(app.config['STATIC_FOLDER'], 'post')


# Ensure the folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER_POSTS']):
    os.makedirs(app.config['UPLOAD_FOLDER_POSTS'])

uri = "mongodb+srv://cadibalinfo:Nevinotech512@cadibal.co2kz.mongodb.net/?retryWrites=true&w=majority&appName=CADIBAL"

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per minute"],
    storage_uri=uri  # MongoDB backend
)
limiter.init_app(app)

# Create a new client and connect to the server
client = MongoClient(uri, server_api=ServerApi('1'))
db = client['CADIBAL']
users_collection = db['users']
videos_collection = db['videos']
jobs_collection = db['jobs']
posts_collection = db['posts'] 
notifications_collection = db['notifications']
ads_collection = db['ads']
messages_collection = db['messages']
admin_collection = db["admin_collection"]
timeline_collection = db["timeline"]

# Define upload directories
UPLOAD_FOLDER_VIDEOS = '/var/www/html/cadibal-media/static/uploads/videos'
UPLOAD_FOLDER_THUMBNAILS = '/var/www/html/cadibal-media/static/uploads/thumbnails'
ALLOWED_VIDEO_EXTENSIONS = {'mp4', 'mov', 'avi', 'mkv'}
ALLOWED_IMAGE_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}
ALLOWED_FILE_EXTENSIONS = {'jpg', 'jpeg', 'png', 'pdf'}
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Configure app
app.config['UPLOAD_FOLDER_VIDEOS'] = UPLOAD_FOLDER_VIDEOS
app.config['UPLOAD_FOLDER_THUMBNAILS'] = UPLOAD_FOLDER_THUMBNAILS

def save_file(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)  # Ensure safe filenames
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)  # Full path to the file
        file.save(file_path)
        return file_path
    return None

def allowed_file(filename, allowed_extensions=None):
    """Check if the file has an allowed extension."""
    # If no custom allowed extensions are provided, use app.config
    if allowed_extensions is None:
        allowed_extensions = app.config['ALLOWED_EXTENSIONS']
    
    # Check if the file has an extension and if it's in the allowed extensions list
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

@app.route('/')
def home():
    return render_template('index.html')

# Define allowed extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Function to check if the file extension is allowed
def allowed_file(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

# Updated route for registering a user
@app.route('/register/user', methods=['GET', 'POST'])
def register_user():
    if request.method == 'POST':
        try:
            # Get form data
            data = request.form
            fname = data.get('firstName')
            lname = data.get('lastName')
            email = data.get('email')
            password = data.get('password')
            phone = data.get('phone')
            gender = data.get('gender')
            dob = data.get('dob')
            skills = data.get('skills')
            education = data.get('education')
            address = {
                'doorNo': data.get('doorNo', 'N/A'),
                'area': data.get('area', 'N/A'),
                'district': data.get('district', 'N/A'),
                'state': data.get('state', 'N/A'),
                'country': data.get('country', 'N/A')
            }

            # Hash password
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            # Save profile photo and get relative path
            profile_photo_path = None
            if 'profilePhoto' in request.files:
                profile_photo = request.files['profilePhoto']
                if profile_photo and allowed_file(profile_photo.filename, ALLOWED_EXTENSIONS):
                    unique_filename = f"{uuid.uuid4()}_{secure_filename(profile_photo.filename)}"
                    profile_photo.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
                    profile_photo_path = f"static/uploads/{unique_filename}"

            # Save banner photo and get relative path
            banner_photo_path = None
            if 'bannerPhoto' in request.files:
                banner_photo = request.files['bannerPhoto']
                if banner_photo and allowed_file(banner_photo.filename, ALLOWED_EXTENSIONS):
                    unique_filename = f"{uuid.uuid4()}_{secure_filename(banner_photo.filename)}"
                    banner_photo.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
                    banner_photo_path = f"static/uploads/{unique_filename}"

            # Prepare user data
            user_data = {
                'user_type': 'user',
                'firstName': fname,
                'lastName': lname,
                'email': email,
                'password': hashed_password,
                'phone': phone,
                'gender': gender,
                'dob': dob,
                'skills': skills,
                'education': education,
                'address': address,
                'profilePhoto': profile_photo_path,
                'bannerPhoto': banner_photo_path
            }

            # Check for duplicate email
            existing_user = users_collection.find_one({'email': email})
            if existing_user:
                return "Email already registered", 400

            # Insert into database
            users_collection.insert_one(user_data)

            # Redirect to login page
            return redirect(url_for('login'))

        except Exception as e:
            return f"An error occurred: {str(e)}", 500

    return render_template('register_user.html')

# Route for registering a organization
@app.route('/register/organization', methods=['GET', 'POST'])
def register_organization():
    if request.method == 'POST':
        try:
            # Get form data
            data = request.form
            name = data.get('orgName')
            email = data.get('orgEmail')
            password = data.get('password')
            startDate = data.get('startDate')
            contactEmail = data.get('contactEmail')
            phone = data.get('phone')
            address = {
                'doorNo': data.get('doorNo', 'N/A'),
                'area': data.get('area', 'N/A'),
                'district': data.get('district', 'N/A'),
                'state': data.get('state', 'N/A'),
                'country': data.get('country', 'N/A')
            }
            organizationType = data.get('orgType')
            description = data.get('description')

            # Hash password
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

             # Save profile photo and get relative path
            profile_photo_path = None
            if 'profilePhoto' in request.files:
                profile_photo = request.files['profilePhoto']
                if profile_photo and allowed_file(profile_photo.filename):
                    unique_filename = f"{uuid.uuid4()}_{secure_filename(profile_photo.filename)}"
                    profile_photo.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
                    # Store only the relative path in the database
                    profile_photo_path = f"static/uploads/{unique_filename}"

            # Save banner photo and get relative path
            banner_photo_path = None
            if 'bannerPhoto' in request.files:
                banner_photo = request.files['bannerPhoto']
                if banner_photo and allowed_file(banner_photo.filename):
                    unique_filename = f"{uuid.uuid4()}_{secure_filename(banner_photo.filename)}"
                    banner_photo.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
                    # Store only the relative path in the database
                    banner_photo_path = f"static/uploads/{unique_filename}"
            
            # Prepare organization data
            organization_data = {
                'user_type': 'organization',
                'name': name,
                'email': email,
                'password': hashed_password,
                'startDate': startDate,
                'contactEmail': contactEmail,
                'phone': phone,
                'address': address,
                'organizationType': organizationType,
                'description': description,
                'profilePhoto': profile_photo_path,
                'bannerPhoto': banner_photo_path
            }

            # Check for duplicate email
            existing_user = users_collection.find_one({'email': email})
            if existing_user:
                return "Email already registered", 400

            # Insert into database
            users_collection.insert_one(organization_data)
            # Redirect to login page
            return redirect(url_for('login'))

        except Exception as e:
            return f"An error occurred: {str(e)}", 500

    return render_template('register_organization.html')

# Function to generate CAPTCHA code
def generate_captcha_code():
    characters = string.ascii_letters + string.digits
    captcha = ''.join(random.choices(characters, k=6))  # Generate 6-character CAPTCHA
    return captcha

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None  # Initialize error variable for error messages
    if request.method == 'POST':
        # Get form data
        email = request.form.get('email')
        password = request.form.get('password')
        captcha_input = request.form.get('captchaInput')

        # Get the CAPTCHA code from session
        captcha_code = session.get('captcha_code')
        
        # Validate CAPTCHA
        if captcha_input != captcha_code:
            error = "Incorrect CAPTCHA. Please try again."
        else:
            # Find the user in the database
            user = users_collection.find_one({'email': email})
            
            if user:
                # Check if password is correct
                if bcrypt.checkpw(password.encode('utf-8'), user['password']):
                    # Set session variables (store user information)
                    session['user_id'] = str(user['_id'])  # Store the user's unique ID
                    session['email'] = user['email']      # Store the user's email
                    session['user_type'] = user.get('user_type')  # Store user type ('user' or 'organization')
                    
                    # Redirect to the appropriate profile page based on user type
                    if user.get('user_type') == 'user':
                        return redirect(url_for('user_profile'))
                    elif user.get('user_type') == 'organization':
                        return redirect(url_for('organization_profile'))
                    else:
                        error = "Unknown user type."
                else:
                    # Password is incorrect
                    error = "Invalid password, please try again."
            else:
                # User not found
                error = "No user found with that email address."

    # Generate CAPTCHA and store it in session
    captcha_code = generate_captcha_code()
    session['captcha_code'] = captcha_code
    
    return render_template('login.html', captcha_code=captcha_code, error=error)


@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Remove user_id from session
    session.pop('email', None)     # Remove email from session
    return redirect(url_for('login'))



@app.route('/user/profile', methods=['GET'])
def user_profile():
    user_id = session.get('user_id')
    
    if not user_id:
        return redirect(url_for('login'))
    
    # Fetch user details
    user = users_collection.find_one({'_id': ObjectId(user_id)})

    if not user:
        return "User not found.", 404
    
    # Redirect if user is not of type 'user'
    if user.get('user_type') != 'user':
        return redirect(url_for('organization_profile'))  # Adjust this to your structure

    # Fetch user's posts from posts_collection by user_id
    posts = posts_collection.find({'user_id': user_id})

    # Convert posts to a list and enhance with additional details
    posts = list(posts)
    for post in posts:
        post['uploaded_at'] = post.get('uploaded_at', None)  # Ensure date is formatted if needed
        publisher = users_collection.find_one({'_id': ObjectId(post.get('uploaded_by'))})
        if publisher:
            post['publisher_name'] = publisher.get('name') or publisher.get('firstName')
            post['publisher_photo'] = publisher.get('profilePhoto')

    return render_template('user_profile.html', user=user, posts=posts)


UPLOAD_DIR = "/static/uploads/post"

@app.route('/delete_post', methods=['POST'])
def delete_post():
    # Get the logged-in user's ID and type from the session
    user_id = session.get('user_id')
    user_type = session.get('user_type')

    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        # Get the post ID from the form data
        post_id = request.form.get('post_id')

        # Validate the post ID
        if not ObjectId.is_valid(post_id):
            return jsonify({'error': 'Invalid post ID'}), 400

        # Fetch the post from the database
        post = posts_collection.find_one({'_id': ObjectId(post_id)})

        if not post:
            return jsonify({'error': 'Post not found'}), 404

        # Check if the logged-in user owns the post
        if str(post.get('user_id')) != user_id:
            return jsonify({'error': 'Unauthorized to delete this post'}), 403

        # Retrieve the photo path
        photo_path = post.get('photo_path')

        if photo_path:
            # Construct the absolute path for the photo
            absolute_path = os.path.join(UPLOAD_DIR, os.path.basename(photo_path))

            print(f"Attempting to delete photo at: {absolute_path}")

            # Check if the file exists before deleting
            if os.path.exists(absolute_path):
                os.remove(absolute_path)
                print(f"Photo successfully deleted: {absolute_path}")
            else:
                print(f"Photo not found at path: {absolute_path}")
        else:
            print("No photo path specified for this post.")

        # Delete the post from the database
        posts_collection.delete_one({'_id': ObjectId(post_id)})
        print(f"Post with ID {post_id} deleted from the database.")

        # Redirect based on user type
        if user_type == 'organization':
            return redirect(url_for('organization_profile'))
        else:
            return redirect(url_for('user_profile'))

    except Exception as e:
        # Log the error
        print(f"Error during post deletion: {e}")
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500


@app.route('/delete_video', methods=['POST'])
def delete_video():
    # Get the logged-in user's ID and user type from the session
    user_id = session.get('user_id')  # Assume `user_id` is stored in the session
    user_type = session.get('user_type')  # Either 'organization' or 'user'

    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        # Get the video ID from the form data
        video_id = request.form.get('video_id')

        # Validate the video ID
        if not ObjectId.is_valid(video_id):
            return jsonify({'error': 'Invalid video ID'}), 400

        # Fetch the video from the database
        video = videos_collection.find_one({'_id': ObjectId(video_id)})

        if not video:
            return jsonify({'error': 'Video not found'}), 404

        # Check if the logged-in user owns the video
        if str(video.get('user_id')) != user_id:
            return jsonify({'error': 'Unauthorized to delete this video'}), 403

        # Delete the video
        videos_collection.delete_one({'_id': ObjectId(video_id)})

        # Redirect back to the same page or a success page
        if user_type == 'organization':
            return redirect(url_for('organization_profile'))
        else:
            return redirect(url_for('user_profile'))
    except Exception as e:
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500

@app.route('/delete_job', methods=['POST'])
def delete_job():
    # Get the logged-in user's ID from the session
    user_id = session.get('user_id')

    if not user_id:
        return redirect(url_for('login'))  # If the user is not logged in, redirect to login

    try:
        # Get the job ID from the form
        job_id = request.form.get('job_id')

        # Validate the job ID
        if not ObjectId.is_valid(job_id):
            return jsonify({'error': 'Invalid job ID'}), 400

        # Fetch the job from the database
        job = jobs_collection.find_one({'_id': ObjectId(job_id)})

        if not job:
            return jsonify({'error': 'Job not found'}), 404

        # Check if the logged-in user is the owner of the job
        if str(job.get('posted_by')) != user_id:
            return jsonify({'error': 'Unauthorized to delete this job'}), 403

        # Delete the job from the database
        jobs_collection.delete_one({'_id': ObjectId(job_id)})

        # Redirect back to the organization profile page after successful deletion
        return redirect(url_for('organization_profile'))

    except Exception as e:
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500


# Route for organization profile
@app.route('/organization/profile', methods=['GET', 'POST'])
def organization_profile():
    user_id = session.get('user_id')
    
    if not user_id:
        # If the user is not logged in, redirect to the login page
        return redirect(url_for('login'))
    
    # Fetch the user's data from the database
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    
    if not user:
        # Handle case where the user is not found
        return "User not found.", 404

    # Check if the user is an organization (user_type == 'organization')
    if user.get('user_type') != 'organization':
        return redirect(url_for('organization_profile')) 
     # Redirect to user profile if the user is not an organization

    # Fetch user's posts from posts_collection by user_id
    posts = posts_collection.find({'user_id': user_id})

    # Convert posts to a list and enhance with additional details
    posts = list(posts)
    for post in posts:
        post['uploaded_at'] = post.get('uploaded_at', None)  # Ensure date is formatted if needed
        publisher = users_collection.find_one({'_id': ObjectId(post.get('uploaded_by'))})
        if publisher:
            post['publisher_name'] = publisher.get('name') or publisher.get('firstName')
            post['publisher_photo'] = publisher.get('profilePhoto')

      # Fetch videos uploaded by the organization from video_collection
    videos = videos_collection.find({'user_id': user_id})
    
    # Convert videos to a list and format additional details
    videos = list(videos)
    for video in videos:
        video['uploaded_at'] = video.get('uploaded_at', None)  # Format or ensure uploaded_at exists
        video['video_id'] = str(video['_id'])  # Ensure video ID is a string for rendering in the template

    # Fetch job listings posted by the organization from jobs_collection
    jobs = jobs_collection.find({'posted_by': user_id})

    # Convert jobs to a list and enhance with additional details
    jobs = list(jobs)
    for job in jobs:
        job['posted_at'] = job.get('posted_at', None)  # Ensure posted_at exists or format it

    is_organization = user.get('user_type') == 'organization'
    return render_template('organization_profile.html', user=user, is_organization=is_organization,posts=posts , videos=videos, jobs=jobs)

@app.route('/edit/profile', methods=['GET', 'POST'])
def edit_profile():
    user_id = session.get('user_id')

    if not user_id:
        return redirect(url_for('login'))

    # Ensure user_id is ObjectId type when querying the database
    user_id_obj = ObjectId(user_id)
    
    user = users_collection.find_one({'_id': user_id_obj})

    if not user:
        return "User not found.", 404

    if request.method == 'POST':
        data = request.form

        # Handle profile photo upload
        profile_photo = request.files.get('profilePhoto')
        banner_photo = request.files.get('bannerPhoto')

        update_data = {}

        if profile_photo and allowed_file(profile_photo.filename):
            # Generate unique filename using UUID
            profile_filename = f"{uuid.uuid4().hex}_{secure_filename(profile_photo.filename)}"
            profile_path = os.path.join(app.config['UPLOAD_FOLDER'], profile_filename)
            profile_photo.save(profile_path)
            update_data['profilePhoto'] = f'static/uploads/{profile_filename}'

            # Check if user_id matches the user in the related collections
            print(f"Updating profile photo for user_id: {user_id_obj}")

            # Ensure user_id is ObjectId when updating related collections
            try:
                print(f"Updating profile photo for user_id: {user_id_obj}")
                posts_result = posts_collection.update_many({'user_id': str(user_id_obj)}, {"$set": {'publisher_photo': update_data['profilePhoto']}})
                print(f"Posts updated: {posts_result.modified_count} document(s)")

                videos_result = videos_collection.update_many({'user_id': str(user_id_obj)}, {"$set": {'publisher_photo': update_data['profilePhoto']}})
                print(f"Videos updated: {videos_result.modified_count} document(s)")

                jobs_result = jobs_collection.update_many({'user_id': str(user_id_obj)}, {"$set": {'publisher_photo': update_data['profilePhoto']}})
                print(f"Jobs updated: {jobs_result.modified_count} document(s)")

                
                # Log how many documents were updated in each collection
                print(f"Posts updated: {posts_result.modified_count} document(s)")
                print(f"Videos updated: {videos_result.modified_count} document(s)")
                print(f"Jobs updated: {jobs_result.modified_count} document(s)")
            except Exception as e:
                print(f"Error while updating related collections: {e}")

        if banner_photo and allowed_file(banner_photo.filename):
            banner_filename = f"{uuid.uuid4().hex}_{secure_filename(banner_photo.filename)}"
            banner_path = os.path.join(app.config['UPLOAD_FOLDER'], banner_filename)
            banner_photo.save(banner_path)
            update_data['bannerPhoto'] = f'static/uploads/{banner_filename}'

        # Handle password update
        new_password = data.get('newPassword')
        confirm_password = data.get('confirmPassword')

        if new_password and confirm_password:
            if new_password == confirm_password:
                hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                update_data['password'] = hashed_password
            else:
                flash('Passwords do not match.', 'error')
                return redirect(url_for('edit_profile'))

        # Update other profile fields
        if user['user_type'] == 'organization':
            update_data.update({
                "name": data.get('name'),
                "description": data.get('description'),
                "phone": data.get('phoneNumber'),
                "address": {
                    'doorNo': data.get('doorNo', 'N/A'),
                    'area': data.get('area', 'N/A'),
                    'district': data.get('district', 'N/A'),
                    'state': data.get('state', 'N/A'),
                    'country': data.get('country', 'N/A')
                }
            })
        else:
            update_data.update({
                "firstName": data.get('firstName'),
                "lastName": data.get('lastName'),
                "email": data.get('email'),
                "phone": data.get('phoneNumber'),
                "address": {
                    'doorNo': data.get('doorNo', 'N/A'),
                    'area': data.get('area', 'N/A'),
                    'district': data.get('district', 'N/A'),
                    'state': data.get('state', 'N/A'),
                    'country': data.get('country', 'N/A')
                }
            })

        # Log update data for debugging
        print(f"Update Data for User: {update_data}")  # Debugging line

        # Save changes to the database for the user
        try:
            result = users_collection.update_one({'_id': user_id_obj}, {"$set": update_data})
            print(f"Database update result for user: {result.modified_count} document(s) updated.")  # Debugging line

            # If update successful, show success message
            flash('Profile updated successfully!', 'success')
        except Exception as e:
            print(f"Error while updating user data: {e}")

        return redirect(url_for('edit_profile'))

    return render_template('edit_profile.html', user=user)




@app.route('/settings', methods=['GET', 'POST'])
def settings():
    user_id = session.get('user_id')
    
    if not user_id:
        # If the user is not logged in, redirect to the login page
        return redirect(url_for('login'))
    
    # Fetch the user's data from the database
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    
    if not user:
        # Handle case where the user is not found
        return "User not found.", 404
    # Add your logic for the settings page here
    return render_template('setting.html')  # Render the settings page template


@app.route('/video_upload', methods=['GET', 'POST'])
def video_upload():
    user_id = session.get('user_id')
    
    if not user_id:
        # Redirect to login if the user is not logged in
        return redirect(url_for('login'))
    
    # Fetch user data from the database (including name, profile photo, and user_type)
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    
    if not user:
        return "User not found.", 404
    
    # Check if the user is an organization (user_type should be 'organization')
    if user.get('user_type') != 'organization':
        # Redirect to a page that users are allowed to access if they are not an organization
        return redirect(url_for('home'))  # Redirect to a home or another appropriate page
    
    if request.method == 'POST':
        # Get form data
        title = request.form.get('title')
        description = request.form.get('description')
        link = request.form.get('link')  # Get the link field from the form
        thumbnail = request.files.get('thumbnail')
        video = request.files.get('video')

        # Validate inputs
        if not title or not description:
            error = "Title and description are required."
            return render_template('video_upload.html', user=user, error=error)

        if not link:
            error = "A link is required."
            return render_template('video_upload.html', user=user, error=error)

        if not thumbnail or not allowed_file(thumbnail.filename, ALLOWED_IMAGE_EXTENSIONS):
            error = "Invalid thumbnail format. Please upload a valid image."
            return render_template('video_upload.html', user=user, error=error)

        if not video or not allowed_file(video.filename, ALLOWED_VIDEO_EXTENSIONS):
            error = "Invalid video format. Please upload a valid video."
            return render_template('video_upload.html', user=user, error=error)

        # Define upload paths
        thumbnail_folder = os.path.join(app.static_folder, 'uploads', 'thumbnails')
        video_folder = os.path.join(app.static_folder, 'uploads', 'videos')
        
        # Ensure the directories exist
        os.makedirs(thumbnail_folder, exist_ok=True)
        os.makedirs(video_folder, exist_ok=True)

        # Save thumbnail
        thumbnail_filename = secure_filename(thumbnail.filename)
        thumbnail_path = os.path.join(thumbnail_folder, thumbnail_filename)
        thumbnail.save(thumbnail_path)

        # Save video
        video_filename = secure_filename(video.filename)
        video_path = os.path.join(video_folder, video_filename)
        video.save(video_path)

        # Convert paths to relative static URLs
        thumbnail_url = f'/static/uploads/thumbnails/{thumbnail_filename}'
        video_url = f'/static/uploads/videos/{video_filename}'

        current_time = datetime.now(pytz.utc)

        # Save video details to the database
        video_data = {
            'title': title,
            'description': description,
            'link': link,                 # Save the link in the database
            'thumbnail': thumbnail_url,  # Save as URL for use in templates
            'video': video_url,          # Save as URL for use in templates
            'user_id': user_id,
            'uploaded_at': current_time,
            'publisher_name': user.get('name'),  # Publisher's name from users_collection
            'publisher_photo': user.get('profilePhoto')  # Publisher's profile photo from users_collection
        }

        # Insert video data into the videos collection
        videos_collection.insert_one(video_data)

        success_message = "Video uploaded successfully!"
        return render_template('video_upload.html', user=user, success=success_message)

    return render_template('video_upload.html', user=user)



@app.route('/job_upload', methods=['GET', 'POST'])
def job_upload():
    user_id = session.get('user_id')
    
    if not user_id:
        # Redirect to login if the user is not logged in
        return redirect(url_for('login'))
    
    # Fetch user data from the database (including the user's name, profile photo, and user_type)
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    
    if not user:
        return "User not found.", 404
    
    # Check if the user is an organization (user_type should be 'organization')
    if user.get('user_type') != 'organization':
        # Redirect to a page that users are allowed to access if they are not an organization
        return redirect(url_for('home'))  # Redirect to home or another appropriate page
    
    if request.method == 'POST':
        # Get form data
        job_title = request.form.get('jobTitle')
        job_domain = request.form.get('jobDomain')
        job_location = request.form.get('jobLocation')
        work_type = request.form.get('workType')
        job_type = request.form.get('jobType')
        experience_level = request.form.get('experienceLevel')
        salary = request.form.get('salary')
        job_description = request.form.get('jobDescription')
        required_qualification = request.form.get('requiredQualification')
        skills_required = request.form.get('skillsRequired')
        application_deadline = request.form.get('applicationDeadline')
        contact_email = request.form.get('contactEmail')
        job_link = request.form.get('jobLink')

        # Validate inputs
        if not job_title or not job_domain or not job_location or not job_description or not required_qualification or not skills_required or not application_deadline or not contact_email or not job_link:
            error = "All required fields must be filled."
            return render_template('job_upload.html', user=user, error=error)

        # Prepare the job data to save in the jobs collection
        job_data = {
            'job_title': job_title,
            'job_domain': job_domain,
            'job_location': job_location,
            'work_type': work_type,
            'job_type': job_type,
            'user_id': user_id,
            'experience_level': experience_level,
            'salary': salary,
            'job_description': job_description,
            'required_qualification': required_qualification,
            'skills_required': skills_required,
            'application_deadline': application_deadline,
            'contact_email': contact_email,
            'email' : user.get('email'), 
            'job_link': job_link,
            'posted_by': user_id,
            'posted_at': datetime.utcnow(),
            'publisher_name': user.get('name'),  # Add the publisher's name
            'publisher_photo': user.get('profilePhoto')  # Add the publisher's profile photo path
        }

        # Insert job data into the jobs collection
        jobs_collection.insert_one(job_data)

        success_message = "Job posted successfully!"
        return render_template('job_upload.html', user=user, success=success_message)

    return render_template('job_upload.html', user=user)

ALLOWED_FILE_EXTENSIONS = {'jpg', 'jpeg', 'png', 'pdf'}

@app.route('/post_upload', methods=['GET', 'POST'])
def post_upload():
    user_id = session.get('user_id')
    
    if not user_id:
        # Redirect to login if user is not logged in
        return redirect(url_for('login'))
    
    # Fetch user data from the database
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    
    if not user:
        return "User not found.", 404
    
    if request.method == 'POST':
        # Get form data
        description = request.form.get('description')
        location = request.form.get('location')
        tag_people = request.form.get('tagPeople')
        email = request.form.get('email')
        uploaded_file = request.files.get('uploadFile')

        # Validate inputs
        if not description or not location or not email:
            error = "Description, location, and email are required."
            return render_template('post_upload.html', user=user, error=error)

        if uploaded_file and allowed_file(uploaded_file.filename, ALLOWED_FILE_EXTENSIONS):
            # Ensure the directory exists
            upload_folder = os.path.join(app.static_folder, 'uploads', 'post')
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder)
            
            # Generate a unique filename
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            file_ext = uploaded_file.filename.rsplit('.', 1)[1].lower()
            unique_filename = f"{user_id}_{timestamp}.{file_ext}"
            file_path = os.path.join(upload_folder, unique_filename)

            # Save the file
            uploaded_file.save(file_path)

            # Relative file path for database
            relative_file_path = os.path.relpath(file_path, app.static_folder)

            # Save post details to the database
            post_data = {
                'description': description,
                'location': location,
                'tag_people': tag_people,
                'email': email,
                'user_id': user_id,
                'file_path': relative_file_path,
                'views': 0,  # Initialize views to 0
                'like_count': 0,  
                'likes':0,
                'liked_by': [] ,   
                'uploaded_at': datetime.now(),
                'publisher_name': user.get('name') or user.get('firstName'),
                'publisher_photo': user.get('profilePhoto')  # User's profile photo
            }

            posts_collection.insert_one(post_data)

            success_message = "Post uploaded successfully!"
            return render_template('post_upload.html', user=user, success=success_message)
        else:
            error = "Invalid file format. Please upload a JPG, JPEG, PNG, or PDF file."
            return render_template('post_upload.html', user=user, error=error)

    return render_template('post_upload.html', user=user)




@app.route('/search', methods=['GET', 'POST'])
def search():
    user_id = session.get('user_id')
    
    if not user_id:
        # If the user is not logged in, redirect to the login page
        return redirect(url_for('login'))
    
    # Fetch the user's data from the database
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    
    if not user:
        # Handle case where the user is not found
        return "User not found.", 404
    
    search_results = []
    
    if request.method == 'POST':
        search_query = request.form.get('search_query')
        
        # If there's a search query, perform the search on the database
        if search_query:
            # Assuming you're searching in users' names and emails
            search_results = users_collection.find({
                '$or': [
                    {'name': {'$regex': search_query, '$options': 'i'}},  # Case-insensitive search
                    {'email': {'$regex': search_query, '$options': 'i'}}
                ]
            })
            search_results = list(search_results)  # Convert cursor to list for easy iteration
    
    return render_template('search.html', user=user, search_results=search_results)
 # Render the settings page template


@app.route('/notification', methods=['GET', 'POST'])
def notification():
    user_id = session.get('user_id')
    
    if not user_id:
        # If the user is not logged in, redirect to the login page
        return redirect(url_for('login'))
    
    # Fetch the user's data from the database
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    
    if not user:
        # Handle case where the user is not found
        return "User not found.", 404
    
    # Fetch the user's notifications from the database (assuming you have a collection for notifications)
    notifications = notifications_collection.find({'user_id': ObjectId(user_id)}).sort('timestamp', -1)
    
    # Fetch the user's posts from the posts collection (assuming your posts collection is structured similarly)
    posts = posts_collection.find({'user_id': ObjectId(user_id)}).sort('timestamp', -1)
    
    # Add any additional logic for notifications here
    
    # Return the template with user, notifications, and posts data
    return render_template('Notification.html', user=user, notifications=notifications, posts=posts)



@app.route('/view_profile/<_id>', methods=['GET'])
def view_profile(_id):
    # Decode the URL parameter if needed
    decoded_user_id = unquote(_id)
    print(f"Received _id: {decoded_user_id}")
    
    # Encode _id (if you need to store it for any reason)
    encoded_user_id = quote(decoded_user_id)
    
    # Get the logged-in user's ID from the session
    user_id = session.get('user_id')

    if not user_id:
        # If the user is not logged in, redirect to the login page
        return redirect(url_for('login'))

    # Fetch the logged-in user's data
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    if not user:
        return "User not found", 404

    # Check if `_id` is a valid ObjectId and fetch the profile accordingly
    profile = None
    if ObjectId.is_valid(decoded_user_id):
        profile = users_collection.find_one({'_id': ObjectId(decoded_user_id)})
    else:
        # Fallback to querying by username or another field
        profile = users_collection.find_one({'username': decoded_user_id})  # Assuming 'username' exists

    if not profile:
        return "Profile not found", 404

    # Serialize the `_id` fields in both `user` and `profile`
    user['_id'] = str(user['_id'])
    profile['_id'] = str(profile['_id'])

    # Check if the logged-in user is already following the profile
    is_following = profile['_id'] in [str(following_id) for following_id in user.get('following', [])]

    # Render the profile page
    return render_template('profile.html', user=user, profile=profile, is_following=is_following)


@app.route('/toggle_follow', methods=['POST'])
def toggle_follow():
    user_id = request.form.get('user_id')
    profile_id = request.form.get('profile_id')
    action = request.form.get('action')

    if not user_id or not profile_id or not action:
        return jsonify({"success": False, "message": "Invalid request data."}), 400

    user = users_collection.find_one({'_id': ObjectId(user_id)})
    profile = users_collection.find_one({'_id': ObjectId(profile_id)})

    if not user or not profile:
        return jsonify({"success": False, "message": "User or profile not found."}), 404

    if action == 'follow':
        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$addToSet': {'following': profile_id}}
        )
        users_collection.update_one(
            {'_id': ObjectId(profile_id)},
            {'$addToSet': {'followers': user_id}}
        )
    elif action == 'unfollow':
        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$pull': {'following': profile_id}}
        )
        users_collection.update_one(
            {'_id': ObjectId(profile_id)},
            {'$pull': {'followers': user_id}}
        )

    # Fetch updated counts
    updated_user = users_collection.find_one({'_id': ObjectId(user_id)})
    updated_profile = users_collection.find_one({'_id': ObjectId(profile_id)})

    return jsonify({
        "success": True,
        "action": action,
        "newFollowerCount": len(updated_profile['followers']),
        "newFollowingCount": len(updated_user['following'])
    })

@app.route('/job.html')
def job():
    user_id = session.get('user_id')

    if not user_id:
        # If the user is not logged in, redirect to the login page
        return redirect(url_for('login'))

    # Fetch the user's data from the database
    user = users_collection.find_one({'_id': ObjectId(user_id)})

    if not user:
        # Handle case where the user is not found
        return "User not found.", 404

    # Fetch all jobs from the jobs collection
    jobs = jobs_collection.find()

    return render_template('job.html', user=user, jobs=jobs)

@app.route('/post_global', methods=['GET', 'POST'])


def post_global():
    user_id = session.get('user_id')

    if not user_id:
        return redirect(url_for('login'))

    user = users_collection.find_one({'_id': ObjectId(user_id)})
    if not user:
        return "User not found.", 404

    # Fetch posts and infer type
    posts = list(posts_collection.find())
    for post in posts:
        file_extension = post['file_path'].split('.')[-1].lower()
        post['type'] = 'pdf' if file_extension == 'pdf' else 'image'

    # Shuffle posts for randomness
    import random
    random.shuffle(posts)

    return render_template('post_global.html', user=user, posts=posts)

@app.route('/like_post', methods=['POST'])
def like_post():
    post_id = request.json.get('post_id')
    user_id = session.get('user_id')

    if not user_id:
        return jsonify({'success': False, 'message': 'User not logged in'}), 401

    post = posts_collection.find_one({'_id': ObjectId(post_id)})
    if not post:
        return jsonify({'success': False, 'message': 'Post not found'}), 404

    # Ensure 'likes' field is always a list
    if not isinstance(post.get('likes', []), list):
        posts_collection.update_one({'_id': ObjectId(post_id)}, {'$set': {'likes': []}})
        post['likes'] = []

    if user_id in post['likes']:
        # User already liked the post; remove their like
        posts_collection.update_one({'_id': ObjectId(post_id)}, {'$pull': {'likes': user_id}})
    else:
        # User hasn't liked the post yet; add their like
        posts_collection.update_one({'_id': ObjectId(post_id)}, {'$addToSet': {'likes': user_id}})

    # Re-fetch to get updated likes
    post = posts_collection.find_one({'_id': ObjectId(post_id)})  
    new_like_count = len(post.get('likes', []))

    return jsonify({
        'success': True,
        'likes': new_like_count,
        'liked_users': post.get('likes', [])  # Return the updated list of user IDs
    })


@app.route('/get_post', methods=['GET'])
def get_post():
    post_id = request.args.get('post_id')
    user_id = session.get('user_id')
    
    if not user_id:
        return jsonify({'success': False, 'message': 'User not logged in.'}), 401

    post = posts_collection.find_one({'_id': ObjectId(post_id)})
    if not post:
        return jsonify({'success': False, 'message': 'Post not found.'}), 404

    # Check if the current user has liked the post
    is_liked = user_id in post['likes'] if 'likes' in post else False
    
    return jsonify({'success': True, 'post': post, 'is_liked': is_liked})


@app.route('/add_comment', methods=['POST'])
def add_comment():
    post_id = request.json.get('post_id')
    comment = request.json.get('comment')
    user_id = session.get('user_id')

    if not user_id:
        return jsonify({'success': False, 'message': 'User not logged in.'}), 401

    # Fetch user's email from the database
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    if not user:
        return jsonify({'success': False, 'message': 'User not found.'}), 404

    user_email = user.get('email', 'No Email')  # Default to 'No Email' if email is not found

    post = posts_collection.find_one({'_id': ObjectId(post_id)})
    if not post:
        return jsonify({'success': False, 'message': 'Post not found.'}), 404

    # Add comment to post
    new_comment = {
        'user_id': user_id,
        'email': user_email,  # Include the Gmail address
        'comment': comment,
        'timestamp': datetime.utcnow()
    }

    posts_collection.update_one({'_id': ObjectId(post_id)}, {'$push': {'comments': new_comment}})
    return jsonify({'success': True, 'comment': new_comment})


@app.route('/post_trending', methods=['GET', 'POST'])
def post_trending():
    user_id = session.get('user_id')
    
    if not user_id:
        # If the user is not logged in, redirect to the login page
        return redirect(url_for('login'))
    
    # Fetch the user's data from the database
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    
    if not user:
        # Handle case where the user is not found
        return "User not found.", 404

    # Fetch the posts from the database
    posts = list(posts_collection.find())  # Ensure this is a list, not a cursor
    for post in posts:
        file_extension = post['file_path'].split('.')[-1].lower()
        post['type'] = 'pdf' if file_extension == 'pdf' else 'image'

        # Ensure 'likes' is a list
        if not isinstance(post.get('likes', []), list):
            post['likes'] = []  # Convert likes to an empty list if not a list

    # Sort posts based on the number of likes (descending order)
    posts.sort(key=lambda post: len(post.get('likes', [])), reverse=True)
    
    return render_template('post_trending.html', user=user, posts=posts)

@app.route('/cc_video', methods=['GET', 'POST'])
def cc_video():
    user_id = session.get('user_id')
    
    if not user_id:
        # If the user is not logged in, redirect to the login page
        return redirect(url_for('login'))
    
    # Fetch the user's data from the database
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    
    if not user:
        # Handle case where the user is not found
        return "User not found.", 404

    # Fetch all videos from the collection
    videos = list(videos_collection.find())

    # Select a random video if there are videos
    random_video = random.choice(videos) if videos else None

    return render_template('cc_video.html', user=user, videos=videos, random_video=random_video)


# Helper function to check allowed file extensions
def allowed_file(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

@app.route('/upload_ad', methods=['GET', 'POST'])
def upload_ad():
    user_id = session.get('user_id')

    if not user_id:
        # If the user is not logged in, redirect to the login page
        return redirect(url_for('login'))

    # Fetch the user's data from the database
    user = users_collection.find_one({'_id': ObjectId(user_id)})

    if not user:
        # Handle case where the user is not found
        return "User not found.", 404

    if request.method == 'POST':
        ad_name = request.form['ad_name']
        ad_description = request.form['ad_description']

        # Ensure the upload directories exist
        image_folder = os.path.join(app.static_folder, 'uploads', 'thumbnails')
        video_folder = os.path.join(app.static_folder, 'uploads', 'videos')
        os.makedirs(image_folder, exist_ok=True)
        os.makedirs(video_folder, exist_ok=True)

        # Debugging: Check if the folders are created successfully
        print(f"Image folder exists: {os.path.exists(image_folder)}")
        print(f"Video folder exists: {os.path.exists(video_folder)}")

        # Handle video upload
        video = request.files.get('ad_video')
        if video and allowed_file(video.filename, ALLOWED_VIDEO_EXTENSIONS):
            video_filename = secure_filename(video.filename)
            video_path = os.path.join(video_folder, video_filename)
            
            # Debugging: Log the path where the video is being saved
            print(f"Saving video to: {video_path}")
            
            video.save(video_path)
            video_url = f'/static/uploads/videos/{video_filename}'
        else:
            # If invalid video file
            return "Invalid video file type", 400

        # Handle thumbnail image upload (optional)
        thumbnail = request.files.get('ad_thumbnail')
        if thumbnail and allowed_file(thumbnail.filename, ALLOWED_IMAGE_EXTENSIONS):
            thumbnail_filename = secure_filename(thumbnail.filename)
            thumbnail_path = os.path.join(image_folder, thumbnail_filename)
            thumbnail.save(thumbnail_path)
            thumbnail_url = f'/static/uploads/thumbnails/{thumbnail_filename}'
        else:
            # If no thumbnail or invalid type, use a default
            thumbnail_url = '/static/uploads/thumbnails/default_thumbnail.jpg'

        # Insert ad details into the ads collection
        try:
            ads_collection.insert_one({
                'name': ad_name,
                'description': ad_description,
                'video_url': video_url,  # Save as relative URL for frontend
                'thumbnail_url': thumbnail_url,  # Save thumbnail URL
                'uploaded_by': user_id,  # Save the user who uploaded the ad
                'uploaded_at': datetime.now(pytz.utc)  # Add a timestamp
            })
            # Debugging: Log the success of the insert
            print(f"Ad uploaded successfully by user {user_id}")
        except Exception as e:
            # If there is an issue inserting the ad into the database
            print(f"Error inserting ad into the database: {e}")
            return "An error occurred while saving the ad", 500

        success_message = "Ad uploaded successfully!"
        return render_template('upload_ad.html', user=user, success=success_message)

    return render_template('upload_ad.html', user=user)


@app.route('/play_video/<video_id>', methods=['GET', 'POST'])
def play_video(video_id):
    user_id = session.get('user_id')
    
    if not user_id:
        return redirect(url_for('login'))
    
    # Fetch the video data using video_id
    video = videos_collection.find_one({'_id': ObjectId(video_id)})
    
    if not video:
        return "Video not found.", 404
    
    # Fetch the user data
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    
    # Ensure 'viewed_ads' and 'liked_videos' fields exist
    if 'viewed_ads' not in user:
        user['viewed_ads'] = []
    if 'liked_videos' not in user:
        user['liked_videos'] = []
    
    # Fetch the ad if available (could be based on a specific condition like random ad or targeted ad)
    all_ads = list(ads_collection.find())
    ad = random.choice(all_ads) if all_ads else None  # Fetching the first ad (you can improve this query)
    
    # Ensure the ad is not viewed by the user yet
    if ad and ad['_id'] not in user.get('viewed_ads', []):
        # Update the user’s viewed_ads field to include the current ad
        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$push': {'viewed_ads': ad['_id']}}  # Add the ad to the viewed_ads list
        )
        
        # Increment the ad view count
        ads_collection.update_one(
            {'_id': ObjectId(ad['_id'])},
            {'$inc': {'view_count': 1}}  # Increment the view count of the ad by 1
        )

    # Update view count if the user hasn't viewed the video already
    if video_id not in user.get('viewed_videos', []):
        # Add video to viewed list of the user
        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$push': {'viewed_videos': video_id}}  # Add video to viewed list
        )
        # Increment the view count in the videos collection
        videos_collection.update_one(
            {'_id': ObjectId(video_id)},
            {'$inc': {'view_count': 1}}  # Increment view count by 1
        )
    
    # Handle the like action if the user clicked the like button
    if request.method == 'POST' and 'like' in request.form:
        if video_id not in user.get('liked_videos', []):  # Check if user hasn't liked the video
            # Increment the like count in the video collection
            videos_collection.update_one(
                {'_id': ObjectId(video_id)},
                {'$inc': {'like_count': 1}}  # Increment like count by 1
            )
            # Add the video to the user's liked list
            users_collection.update_one(
                {'_id': ObjectId(user_id)},
                {'$push': {'liked_videos': video_id}}  # Add video to liked list
            )
    
    # Render the play_video.html template, passing the user, video, and ad data
    return render_template('play_video.html', user=user, video=video, ad=ad)


@app.route('/like_video/<video_id>', methods=['POST'])
def like_video(video_id):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'User not logged in'}), 401
    
    # Fetch the video data using video_id
    video = videos_collection.find_one({'_id': ObjectId(video_id)})
    if not video:
        return jsonify({'error': 'Video not found'}), 404
    
    # Fetch the user data
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    
    # Ensure 'liked_videos' field exists
    if 'liked_videos' not in user:
        user['liked_videos'] = []
    
    # Handle the like/dislike action
    if video_id in user.get('liked_videos', []):  # Check if the user has liked the video
        # Decrement the like count in the video collection (dislike)
        videos_collection.update_one(
            {'_id': ObjectId(video_id)},
            {'$inc': {'like_count': -1}}  # Decrement like count by 1
        )
        # Remove the video from the user's liked list
        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$pull': {'liked_videos': video_id}}  # Remove video from liked list
        )
    else:
        # Increment the like count in the video collection (like)
        videos_collection.update_one(
            {'_id': ObjectId(video_id)},
            {'$inc': {'like_count': 1}}  # Increment like count by 1
        )
        # Add the video to the user's liked list
        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$push': {'liked_videos': video_id}}  # Add video to liked list
        )
    
    # Return the new like count
    new_like_count = videos_collection.find_one({'_id': ObjectId(video_id)})['like_count']
    return jsonify({'new_like_count': new_like_count})



    
@app.route('/cc_trending', methods=['GET', 'POST'])
def cc_trending():
    user_id = session.get('user_id')
    
    if not user_id:
        # If the user is not logged in, redirect to the login page
        return redirect(url_for('login'))
    
    # Fetch the user's data from the database
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    
    if not user:
        # Handle case where the user is not found
        return "User not found.", 404

    # Fetch videos from the database, sorted by the number of likes (descending)
    videos = videos_collection.find().sort('like_count', -1)  # Sort by 'likes' field in descending order
    
    return render_template('cc_trending.html', user=user, videos=videos)

@app.route('/message', methods=['GET', 'POST'])
def message():
    user_id = session.get('user_id')
    
    if not user_id:
        return redirect(url_for('login'))

    user = users_collection.find_one({'_id': ObjectId(user_id)})
    
    if not user:
        return "User not found.", 404

    if request.method == 'POST':
        # Handling message sending
        receiver_id = request.form.get('receiver_id')
        message_content = request.form.get('message')

        if not receiver_id or not message_content:
            flash('Receiver and message content are required!', 'error')
            return redirect(url_for('message'))
        
        # Save message to the database
        message_data = {
            'sender_id': ObjectId(user_id),
            'receiver_id': ObjectId(receiver_id),
            'message': message_content,
            'timestamp': datetime.utcnow(),
            'status': 'sent'
        }

        messages_collection.insert_one(message_data)
        flash('Message sent successfully!', 'success')

    # Fetch conversations for the logged-in user
    conversations = messages_collection.aggregate([
        {
            '$match': {
                '$or': [
                    {'sender_id': ObjectId(user_id)},
                    {'receiver_id': ObjectId(user_id)}
                ]
            }
        },
        {
            '$sort': {'timestamp': -1}
        },
        {
            '$group': {
                '_id': {
                    '$cond': [
                        {'$eq': ['$sender_id', ObjectId(user_id)]},
                        '$receiver_id',
                        '$sender_id'
                    ]
                },
                'last_message': {'$first': '$message'},
                'timestamp': {'$first': '$timestamp'}
            }
        }
    ])

    conversations = [
        {
            'user_id': str(conv['_id']),
            'last_message': conv['last_message'],
            'timestamp': conv['timestamp']
        }
        for conv in conversations
    ]

    # Fetch the list of users that the logged-in user is following
    following_ids = user.get('following', [])
    following_users = users_collection.find({
        '_id': {'$in': [ObjectId(fid) for fid in following_ids]}
    })
    
    following_users_list = [
    {
        'user_id': str(following_user['_id']),
        'type': 'organization' if 'name' in following_user else 'user',
        'name': following_user.get('name') if 'name' in following_user else following_user.get('firstName', 'No Name'),
        'profilePhoto': following_user.get('profilePhoto', 'default.jpg'),
        'email': following_user.get('email', 'No Email'),
          # Set a default profile photo if not available
    }
    for following_user in following_users
]

    return render_template('message.html', user=user, conversations=conversations, following_users=following_users_list)


@app.route('/send_message', methods=['POST'])
def send_message():
    user_id = session.get('user_id')
    
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json
    receiver_id = data.get('receiver_id')
    message_content = data.get('message')

    if not receiver_id or not message_content:
        return jsonify({'error': 'Receiver ID and message content are required'}), 400

    # Save the message in the database
    message_data = {
        'sender_id': user_id,
        'receiver_id': receiver_id,
        'message': message_content,
        'timestamp': datetime.utcnow(),
        'status': 'sent'
    }

    messages_collection.insert_one(message_data)

    return jsonify({'success': 'Message sent successfully'}), 200


@app.route('/get_messages/<receiver_id>', methods=['GET'])
def get_messages(receiver_id):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    last_timestamp = request.args.get('last_timestamp')  # Optional timestamp filter
    query = {
        '$or': [
            {'sender_id': user_id, 'receiver_id': receiver_id},
            {'sender_id': receiver_id, 'receiver_id': user_id}
        ]
    }
    if last_timestamp:
        query['timestamp'] = {'$gt': datetime.fromisoformat(last_timestamp)}

    messages = list(messages_collection.find(query).sort('timestamp', 1))
    for message in messages:
        message['_id'] = str(message['_id'])
    return jsonify(messages), 200


# Celery task to delete old messages
@celery.task
def delete_old_messages():
    try:
        time_limit = datetime.utcnow() - timedelta(hours=1)
        result = messages_collection.delete_many({"timestamp": {"$lt": time_limit}})
        logger.info(f"Deleted {result.deleted_count} old messages.")
    except Exception as e:
        logger.error(f"Error deleting old messages: {e}")

@app.route('/ads/price', methods=['GET'])
def ads():
    return render_template('ads.html')


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Fetch user from MongoDB
        admin_user = admin_collection.find_one({"username": username})

        if admin_user and check_password_hash(admin_user['password'], password):
            # Login successful
            session['admin_logged_in'] = True
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('admin_login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        flash('You must log in to access the admin dashboard.', 'warning')
        return redirect(url_for('admin_login'))
    
    # Fetch all users from the database
    users = users_collection.find()
    return render_template('admin.html', users=users)

@app.route('/admin/delete_user/<user_id>', methods=['POST'])
def delete_user(user_id):
    if not session.get('admin_logged_in'):
        flash('You must log in to perform this action.', 'warning')
        return redirect(url_for('admin_login'))

    # Delete user by ID
    users_collection.delete_one({"_id": ObjectId(user_id)})
    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/logout')
def admin_logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('admin_login'))

@app.route('/admin/posts')
def admin_posts():
    if not session.get('admin_logged_in'):
        flash('You must log in to access the admin dashboard.', 'warning')
        return redirect(url_for('admin_login'))
    
    # Fetch all posts from the database
    posts = posts_collection.find()
    return render_template('admin_post.html', posts=posts)

@app.route('/admin/delete_posts/<post_id>', methods=['POST'])
def delete_posts(post_id):
    if not session.get('admin_logged_in'):
        flash('You must log in to perform this action.', 'warning')
        return redirect(url_for('admin_login'))

    # Delete post by ID
    posts_collection.delete_one({"_id": ObjectId(post_id)})
    flash('Post deleted successfully.', 'success')
    return redirect(url_for('admin_posts'))

@app.route('/admin/videos')
def admin_videos():
    if not session.get('admin_logged_in'):
        flash('You must log in to access the admin dashboard.', 'warning')
        return redirect(url_for('admin_login'))
    
    # Fetch all videos from the database
    videos = videos_collection.find()
    return render_template('admin_videos.html', videos=videos)

@app.route('/admin/delete_videos/<video_id>', methods=['POST'])
def delete_videos(video_id):
    if not session.get('admin_logged_in'):
        flash('You must log in to perform this action.', 'warning')
        return redirect(url_for('admin_login'))

    # Delete video by ID
    videos_collection.delete_one({"_id": ObjectId(video_id)})
    flash('Video deleted successfully.', 'success')
    return redirect(url_for('admin_videos'))


@app.route('/admin/job')
def admin_jobs():
    if not session.get('admin_logged_in'):
        flash('You must log in to access the admin dashboard.', 'warning')
        return redirect(url_for('admin_login'))
    
    # Fetch all jobs from the database
    jobs = jobs_collection.find()
    return render_template('admin.jobs.html', jobs=jobs)

@app.route('/admin/delete_jobs/<job_id>', methods=['POST'])
def delete_jobs(job_id):
    if not session.get('admin_logged_in'):
        flash('You must log in to perform this action.', 'warning')
        return redirect(url_for('admin_login'))

    # Delete job by ID
    jobs_collection.delete_one({"_id": ObjectId(job_id)})
    flash('Job deleted successfully.', 'success')
    return redirect(url_for('admin_jobs'))

@app.route('/admin/ads')
def admin_ads():
    if not session.get('admin_logged_in'):
        flash('You must log in to access the admin dashboard.', 'warning')
        return redirect(url_for('admin_login'))
    
    # Fetch all ads from the database
    ads = ads_collection.find()
    return render_template('admin_ads.html', ads=ads)

@app.route('/admin/delete_ad/<ad_id>', methods=['POST'])
def delete_ad(ad_id):
    if not session.get('admin_logged_in'):
        flash('You must log in to perform this action.', 'warning')
        return redirect(url_for('admin_login'))

    # Delete ad by ID
    ads_collection.delete_one({"_id": ObjectId(ad_id)})
    flash('Ad deleted successfully.', 'success')
    return redirect(url_for('admin_ads'))



@app.route('/follower')
def follower():
    # Check if the user is logged in
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    # Fetch the logged-in user's details
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    if not user:
        flash('User not found!', 'danger')
        return redirect(url_for('login'))

    # Fetch the list of followers
    # Assuming `followers` is a list of user IDs stored in the logged-in user's document
    follower_ids = user.get('followers', [])
    followers = list(users_collection.find({'_id': {'$in': [ObjectId(fid) for fid in follower_ids]}}))

    return render_template('follower.html', user=user, followers=followers)


@app.route('/following')
def following():
    # Check if the user is logged in
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    # Fetch the logged-in user's details
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    if not user:
        flash('User not found!', 'danger')
        return redirect(url_for('login'))

    # Fetch the list of users the logged-in user is following
    # Assuming `following` is a list of user IDs stored in the logged-in user's document
    following_ids = user.get('following', [])
    following = list(users_collection.find({'_id': {'$in': [ObjectId(fid) for fid in following_ids]}}))

    return render_template('following.html', user=user, following=following)



from datetime import datetime


@app.route('/timeline/uploads', methods=['GET', 'POST'])
def timeline_uploads():
    user_id = session.get('user_id')
    
    if not user_id:
        # Redirect to login if the user is not logged in
        return redirect(url_for('login'))
    
    # Fetch user data from the database (including the user's name, profile photo, and user_type)
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    
    if request.method == 'POST':
        # Retrieve event data from the form
        event_name = request.form.get('eventName')
        description = request.form.get('description')
        event_place = request.form.get('eventPlace')
        event_date = request.form.get('eventDate')
        project_name = request.form.get('projectName')
        your_contribution = request.form.get('yourContribution')

        # Handle file upload
        file = request.files.get('uploadFile')
        if file and allowed_file(file.filename):
            # Generate a unique filename to avoid conflicts
            unique_filename = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
            file_path = f"static/uploads/timeline/{unique_filename}"
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            # Save the file
            file.save(file_path)
        else:
            file_path = None  # If no file is uploaded or file type is not allowed
        
        # Prepare event data to be saved in the database
        event_data = {
            'user_id': ObjectId(user_id),
            'event_name': event_name,
            'description': description,
            'event_place': event_place,
            'event_date': event_date,
            'project_name': project_name,
            'your_contribution': your_contribution,
            'file_path': file_path,
            'created_at': datetime.now()
        }
        
        # Save the event data to the timeline collection
        timeline_collection.insert_one(event_data)
        
        # Redirect to a page showing the uploaded events or a success message
        return redirect(url_for('timeline_uploads', success='Event uploaded successfully!'))
    
    # Render the upload page
    return render_template('timeline_uploads.html', user=user)


from datetime import datetime
from bson import ObjectId

@app.route('/timeline')
def timeline():
    user_id = session.get('user_id')
    
    if not user_id:
        # Redirect to login if the user is not logged in
        return redirect(url_for('login'))
    
    # Fetch user data from the database (including the user's name, profile photo, and user_type)
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    
    # Fetch timeline data from the timeline_collection
    timeline_items_cursor = timeline_collection.find({'user_id': ObjectId(user_id)}).sort('created_at', 1)
    
    # Convert timeline_items to a list and parse event_date
    timeline_items = []
    for item in timeline_items_cursor:
        if "event_date" in item and isinstance(item["event_date"], str):
            try:
                # Convert the string to a datetime object (adjust the format as necessary)
                item["event_date"] = datetime.strptime(item["event_date"], "%Y-%m-%d")
            except ValueError:
                pass  # If parsing fails, leave the date as is
        timeline_items.append(item)
    
    return render_template('timeline.html', user=user, timeline_items=timeline_items)

@app.route('/timeline/delete/<event_id>', methods=['POST'])
def timeline_delete(event_id):
    user_id = session.get('user_id')
    
    if not user_id:
        # Redirect to login if the user is not logged in
        return redirect(url_for('login'))
    
    # Fetch user data
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    
    # Find and delete the event by event_id
    event = timeline_collection.find_one({'_id': ObjectId(event_id), 'user_id': ObjectId(user_id)})
    
    if event:
        # Delete event
        timeline_collection.delete_one({'_id': ObjectId(event_id)})
        flash('Event deleted successfully!', 'success')
    else:
        flash('Event not found or you do not have permission to delete this event.', 'danger')
    
    return redirect(url_for('timeline'))


@app.route('/view/timeline/<_id>', methods=['GET'])
def view_timeline(_id):
    logged_in_user_id = session.get('user_id')
    
    if not logged_in_user_id:
        return redirect(url_for('login'))
    
    # Fetch the logged-in user from the database
    user = users_collection.find_one({'_id': ObjectId(logged_in_user_id)})
    
    if not user:
        return "User not found", 404
    
    # Fetch the timeline posts for the given user ID
    timeline_posts = list(timeline_collection.find({'user_id': ObjectId(_id)}).sort('created_at', -1))

    # If there are no timeline posts for the user, return a message
    if not timeline_posts:
        return render_template('view_timeline.html', user=user, timeline_posts=[])

    # Ensure the event_date is a datetime object, format it, and ensure the data is ready for rendering
    for post in timeline_posts:
        if isinstance(post.get('event_date'), str):  # If event_date is a string, convert it to datetime
            post['event_date'] = datetime.strptime(post['event_date'], '%Y-%m-%d')  # Adjust format as needed
        elif isinstance(post.get('event_date'), datetime):  # If already a datetime object, format it directly
            post['event_date'] = post['event_date'].strftime('%B %d, %Y')

    # Pass user and timeline_posts to the template
    return render_template('view_timeline.html', user=user, timeline_posts=timeline_posts)


@app.route('/view/follower/<user_id>')
def view_follower(user_id):
    user_id = session.get('user_id')
    
    if not user_id:
        # Redirect to login if the user is not logged in
        return redirect(url_for('login'))
    # Fetch user data for the specified user_id (not the logged-in user)
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    
    if not user:
        return "User not found", 404
    
    # Debug: Check if the 'followers' field exists and is populated
    print("User's Followers:", user.get('followers', []))
    
    # Get the followers list (if exists), default to empty list if missing
    follower_ids = user.get('followers', [])
    
    # Convert follower_ids to ObjectId if they are strings
    follower_ids = [ObjectId(f) if isinstance(f, str) else f for f in follower_ids]

    # Debug: Print the follower_ids to ensure they are ObjectIds
    print("Follower IDs:", follower_ids)

    # Fetch the full user data for each follower
    if follower_ids:
        followers = list(users_collection.find({'_id': {'$in': follower_ids}}))
        print("Fetched Followers:", followers)  # Debug: Print fetched followers
    else:
        followers = []

    # Debug: Check if followers data was returned correctly
    print("Followers Data:", followers)
    
    return render_template('view_follower.html', user=user, followers=followers)




@app.route('/view/following')
def view_following():
    user_id = session.get('user_id')
    
    if not user_id:
        # Redirect to login if the user is not logged in
        return redirect(url_for('login'))
    
    # Fetch user data
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    
    
    return redirect(url_for('view_following'))


@app.route('/flask/upload')
def flask_upload():
    user_id = session.get('user_id')
    
    if not user_id:
        # Redirect to login if the user is not logged in
        return redirect(url_for('login'))
    
    # Fetch user data from the database (including the user's name, profile photo, and user_type)
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    
    return render_template('flask_uploads.html',user=user)


@app.route('/flask')
def flask():
    user_id = session.get('user_id')
    
    if not user_id:
        # Redirect to login if the user is not logged in
        return redirect(url_for('login'))
    
    # Fetch user data from the database (including the user's name, profile photo, and user_type)
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    
    return render_template('flask.html',user=user)



if __name__ == '__main__':
    app.debug = True
    app.run()


