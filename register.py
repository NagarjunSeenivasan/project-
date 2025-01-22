from flask import request, render_template, redirect, url_for
import bcrypt
import uuid
from werkzeug.utils import secure_filename
from config.include import users_collection, ALLOWED_EXTENSIONS, UPLOAD_FOLDER
import os

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def register_user():
    if request.method == 'POST':
        data = request.form
        fname = data.get('firstName')
        lname = data.get('lastName')
        email = data.get('email')
        password = data.get('password')
        # Add additional fields here...

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        profile_photo_path = None
        banner_photo_path = None

        if 'profilePhoto' in request.files:
            profile_photo = request.files['profilePhoto']
            if profile_photo and allowed_file(profile_photo.filename):
                unique_filename = f"{uuid.uuid4()}_{secure_filename(profile_photo.filename)}"
                profile_photo.save(os.path.join(UPLOAD_FOLDER, unique_filename))
                profile_photo_path = f"static/uploads/{unique_filename}"

        if 'bannerPhoto' in request.files:
            banner_photo = request.files['bannerPhoto']
            if banner_photo and allowed_file(banner_photo.filename):
                unique_filename = f"{uuid.uuid4()}_{secure_filename(banner_photo.filename)}"
                banner_photo.save(os.path.join(UPLOAD_FOLDER, unique_filename))
                banner_photo_path = f"static/uploads/{unique_filename}"

        user_data = {
            'user_type': 'user',
            'firstName': fname,
            'lastName': lname,
            'email': email,
            'password': hashed_password,
            'profilePhoto': profile_photo_path,
            'bannerPhoto': banner_photo_path
        }

        # Check for existing email and save
        existing_user = users_collection.find_one({'email': email})
        if existing_user:
            return "Email already registered", 400
        users_collection.insert_one(user_data)
        return redirect(url_for('login'))

    return render_template('register_user.html')
