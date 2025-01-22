from flask import request, render_template, redirect, url_for, session
import bcrypt
from config.include import users_collection
from public import generate_captcha_code

# Login route
def login():
    error = None  # Initialize error variable for error messages
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        captcha_input = request.form.get('captchaInput')

        captcha_code = session.get('captcha_code')

        # Validate CAPTCHA
        if captcha_input != captcha_code:
            error = "Incorrect CAPTCHA. Please try again."
        else:
            user = users_collection.find_one({'email': email})
            if user:
                if bcrypt.checkpw(password.encode('utf-8'), user['password']):
                    session['user_id'] = str(user['_id'])
                    session['email'] = user['email']
                    session['user_type'] = user.get('user_type')
                    
                    if user.get('user_type') == 'user':
                        return redirect(url_for('user_profile'))
                    elif user.get('user_type') == 'organization':
                        return redirect(url_for('organization_profile'))
                    else:
                        error = "Unknown user type."
                else:
                    error = "Invalid password, please try again."
            else:
                error = "No user found with that email address."

    captcha_code = generate_captcha_code()
    session['captcha_code'] = captcha_code
    
    return render_template('login.html', captcha_code=captcha_code, error=error)

# Logout route
def logout():
    session.pop('user_id', None)
    session.pop('email', None)
    return redirect(url_for('login'))
