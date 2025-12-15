from flask import Flask, request, render_template, redirect, url_for, send_file
from encryption import encrypt_file, decrypt_file
from auth import hash_password, verify_password
import os

app = Flask(__name__)
UPLOAD_FOLDER = 'static'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Mock user data (username: hashed password)
users = {"admin": hash_password("password")}

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            # Save the uploaded file
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(file_path)
            
            # Generate a random encryption key
            key = os.urandom(16)
            
            # Encrypt the file
            encrypt_file(file_path, key)
            
            # Inform the user about the key
            return f"File encrypted and uploaded successfully! Key: {key.hex()}"
    return render_template('upload.html')

@app.route('/download', methods=['GET', 'POST'])
def download():
    if request.method == 'POST':
        try:
            # Get the decryption key
            key = bytes.fromhex(request.form['key'])
            
            # Get the uploaded file
            file = request.files['file']
            if not file:
                return "No file uploaded!"
            
            # Save the file temporarily
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(file_path)
            
            # Extract original file name (assume encrypted files have `.enc` extension)
            if file.filename.endswith('.enc'):
                original_file_name = file.filename[:-4]  # Remove `.enc` extension
            else:
                original_file_name = file.filename
            
            # Decrypt the file
            decrypted_content = decrypt_file(file_path, key)
            
            # Save the decrypted file with the original name
            decrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], original_file_name)
            with open(decrypted_file_path, 'wb') as dec_file:
                dec_file.write(decrypted_content)
            
            # Automatically trigger the download for the decrypted file
            return send_file(decrypted_file_path, as_attachment=True)
        
        except ValueError:
            return "Invalid decryption key format! Please enter a valid hex key."
        except Exception as e:
            return f"An error occurred: {e}"
    
    # Render the download form if it's a GET request
    return render_template('download.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get username and password from the form
        username = request.form['username']
        password = request.form['password']
        
        # Authenticate the user
        if username in users and verify_password(users[username], password):
            return redirect(url_for('upload'))
        return "Invalid credentials"
    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)
