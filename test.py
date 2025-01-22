from flask import Flask,request,render_template
from register import register_user
from uploads import save_file
from job import add_job, get_jobs
from public import generate_captcha_code
import string
import random


app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

# Routes
@app.route('/register/user', methods=['GET', 'POST'])
def user_registration():
    return register_user()

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    file_path = save_file(file)
    if file_path:
        return f"File uploaded successfully: {file_path}"
    return "File upload failed"

# Function to generate CAPTCHA code
def generate_captcha_code():
    characters = string.ascii_letters + string.digits
    captcha = ''.join(random.choices(characters, k=6))  # Generate 6-character CAPTCHA
    return captcha


@app.route('/jobs', methods=['GET', 'POST'])
def jobs():
    if request.method == 'POST':
        job_data = request.form
        add_job(job_data)
        return "Job added successfully"
    return render_template('jobs.html', jobs=get_jobs())

if __name__ == '__main__':
    app.run(debug=True)
