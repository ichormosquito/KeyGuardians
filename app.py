from flask import Flask, render_template, redirect, request, url_for, make_response, jsonify
from pymongo import MongoClient
from hashlib import sha256
import html
import bcrypt
from uuid import uuid4
import uuid
import re
import json
from bson import ObjectId
import os
import base64
import secrets
import hashlib
from Crypto.Cipher import AES
from werkzeug.utils import secure_filename
from flask import send_file


app = Flask(__name__,static_url_path='/static')


mongo_client = MongoClient("mongodb://mongo:27017/")
db = mongo_client["secureDove"]
usercred_collection = db["credentials"]
message_collection = db["messages"]



@app.route('/')
def home():
    authtoken = request.cookies.get('authtoken')

    hashedtoken = (sha256(str(authtoken).encode('utf-8'))).hexdigest()

    user = usercred_collection.find_one({"authtoken": hashedtoken})

    if not user:
        return redirect(url_for('login'))

    return render_template('home.html')
        
@app.route('/message')
def message():
    authtoken = request.cookies.get('authtoken')

    hashedtoken = (sha256(str(authtoken).encode('utf-8'))).hexdigest()

    user = usercred_collection.find_one({"authtoken": hashedtoken})

    if not user:
        return redirect(url_for('login'))

    return render_template('messageFriends.html', user=user)




@app.route('/login', methods=['GET', 'POST'])
def login():

    authtoken = request.cookies.get('authtoken')
    hashedtoken = (sha256(str(authtoken).encode('utf-8'))).hexdigest()
    user = usercred_collection.find_one({"authtoken": hashedtoken})
    if user:
        return redirect(url_for('home'))

    if request.method == 'POST':
        identifier = request.form.get('identifier')
        password = request.form.get('password')

        #prepare identifier for db lookup
        safeidentifier = html.escape(identifier)

        #find user by identifier in db
        user = usercred_collection.find_one({"$or": [{"username": safeidentifier},{"email": safeidentifier}]})

        if not user:
            return render_template('login.html', error="username or email not found, please register.")
        
        elif bcrypt.checkpw(password.encode('utf-8'), user["password"].encode('utf-8')):
            userid = user.get("userid")
            authtoken = uuid4()

            hashedtoken = (sha256(str(authtoken).encode('utf-8'))).hexdigest()

            usercred_collection.update_one({"userid": userid}, {"$set": {"authtoken": hashedtoken}})

            response = make_response(redirect(url_for('home')))
            response.set_cookie('authtoken', str(authtoken), max_age = 60 * 60, httponly=True)

            return response
        
        else:
            return render_template('login.html', error="Incorrect Password, Please try again")
        
    return render_template('login.html')





@app.route('/register', methods = ['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        verification = request.form.get('passwordconf')

        if verification != password:
            return render_template('register.html', error="Passwords dont't match")
        
        # Validate email format
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return render_template('register.html', error="Please make sure email is valid")
        
        #sanitize inputs
        safeusername = html.escape(username)
        safeemail = html.escape(email)

        #find user by identifier in db
        user = usercred_collection.find_one({"$or": [{"username": safeusername},{"email": safeemail}]})

        if not user:
            # Generate a unique userid & authtoken
            userid = str(uuid.uuid4())
            authtoken = uuid4()

            salt = bcrypt.gensalt(rounds=12)  
            hashedpassword = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

            is_valid, message = validate_password(password)
            if not is_valid:
                return render_template('register.html', error=message)
            
            hashedtoken = (sha256(str(authtoken).encode('utf-8'))).hexdigest()
            
            #if password is valid proceed to register user
            registered_user = {
                "userid": userid,  
                "username": safeusername,
                "password": hashedpassword,
                "email": safeemail,
                "authtoken": hashedtoken
            }

            usercred_collection.insert_one(registered_user)
            response = make_response(redirect(url_for('home')))
            response.set_cookie('authtoken', str(authtoken), max_age = 60 * 60, httponly=True)

            return response
        
        else:
            username_exists = user.get("username") == username
            email_exists = user.get("email") == email

            if username_exists and email_exists:
                return render_template('register.html', error="An account with this username and email already exists. Please log in.")
            elif username_exists:
                return render_template('register.html', error="Username already exists, please choose a different one.")
            elif email_exists:
                return render_template('register.html', error="Email already registered, please log in or use a different email.")

    return render_template('register.html')


#helper functions (kept from his code, no duplication)
def validate_password(password):
    
    has_lower = False
    has_upper = False
    has_digit = False
    has_special = False

    for char in password:
        if char.islower():
            has_lower = True
        elif char.isupper():
            has_upper = True
        elif char.isdigit():
            has_digit = True
        elif char in {'!', '@', '#', '$', '%', '^', '&', '(', ')', '-', '_', '='}:
            has_special = True

    if len(password) < 8 or not has_lower or not has_upper or not has_digit or not has_special:
        return False, "Please make sure your password is at least 8 characters long, contains at least one lowercase letter, one uppercase letter, one digit, and a special character (e.g., !, @, #)."

    # If all checks pass
    return True, ""


@app.route('/send_message', methods=['POST'])
def send_message():
    if request.method == 'POST':
        auth_token = request.cookies.get('authtoken')
        # Checks if user has auth token
        if auth_token:
            
            print(f"Auth Token: {auth_token}")
            # Gets user info from database collection 
            hashedtoken = (sha256(str(auth_token).encode('utf-8'))).hexdigest()

            user_in_database = usercred_collection.find_one({"authtoken": hashedtoken})

            if user_in_database:
                print(f"User is: {user_in_database['username']}")
                username = user_in_database['username']

                # Get message and recipient
                data = request.get_json()
                message = data.get('message')
                recipient = data.get('recipient')

                message = html.escape(message)

                print(f"Recipient: {recipient}")
                print((f"Message: {message}"))

                if not message or not recipient:
                    print ("Message and recipient required")
                    return jsonify({"error": "message and recipient required."}), 400
                
                # Check if recipient exists in db
                recipient_user = usercred_collection.find_one({"username": recipient})
                if not recipient_user:
                    return jsonify({"error": "unknown user"}), 400

                # Save message into database
                stored_message = {
                    "sender": username,
                    "recipient": recipient,
                    "message": message
                }

                add_message = message_collection.insert_one(stored_message)
                stored_message["_id"] = str(add_message.inserted_id)

                return jsonify(stored_message)


            if not user_in_database:
                print("User records not found")
                return jsonify({"error": "User records not found"}), 404

        else:
            return jsonify({"error": "Authtoken not found"}), 401



@app.route('/get_messages', methods=['GET'])
def get_messages():
    #find user by authtoken
    auth_token = request.cookies.get('authtoken')
    if auth_token:
        hashedtoken = (sha256(str(auth_token).encode('utf-8'))).hexdigest()
        user_in_database = usercred_collection.find_one({"authtoken": hashedtoken})

        if user_in_database: # If user is found in database, get and return messages
            username = user_in_database['username']
            messages = list(message_collection.find({
                '$or': [{'sender': username}, {'recipient': username}]
            }))

            for message in messages:
                message['_id'] = str(message['_id'])  
            return jsonify({'messages': messages, 'username': username}) # Ret messages and username

        else:
            return jsonify({"error": "User records not found"}), 404
    else:
        return jsonify({"error": "Authtoken not found"}), 401

@app.after_request
def set_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


@app.route('/account',methods=['GET','POST'])#accound page lets you view or update info
def account():
    authtoken = request.cookies.get('authtoken')#check cookies for auth token
    if not authtoken:
        return redirect(url_for('login'))
    hashedtoken=sha256(authtoken.encode('utf-8')).hexdigest()#hashing token
    user =usercred_collection.find_one({"authtoken":hashedtoken})
    if not user:
        return redirect(url_for('login'))
    if request.method=='POST':#allowing user to request updates to email or password
        new_email =request.form.get('email')
        new_password =request.form.get('password')
        update_fields ={}
        if new_email:
            update_fields["email"] = html.escape(new_email)
        if new_password and len(new_password.strip())>0:
            salt = bcrypt.gensalt(rounds=12)
            hashed_password= bcrypt.hashpw(new_password.encode('utf-8'), salt).decode('utf-8')#hashing new pass
            update_fields["password"] = hashed_password
        if update_fields:
            usercred_collection.update_one({"userid": user["userid"]}, {"$set": update_fields})#update database with new acc info
        return redirect(url_for('account'))#refresh account page to reflect the changes
    return render_template('account.html',user=user)

@app.route('/delete_account', methods=['POST'])#allows the user to delete the account
def delete_account():
    authtoken=request.cookies.get('authtoken')#first we get the users auth token
    if not authtoken:
       return render_template('login.html',error="Not Logged Into An Account To Delete.")

    hashedtoken =sha256(authtoken.encode('utf-8')).hexdigest()
    user =usercred_collection.find_one({"authtoken": hashedtoken})
    if user:
        usercred_collection.delete_one({"userid": user["userid"]})#finds user and delete account
        response=make_response(redirect(url_for('register')))# makes sure to remove the auth token from cookies and goes back to account registration
        response.delete_cookie('authtoken')
        return response
    return redirect(url_for('login'))# go back to login 


@app.route('/logout')
def logout():
    response =make_response(redirect(url_for('login')))#after loggin out, bring back to login page
    response.delete_cookie('authtoken')#remove auth token
    return response

UPLOAD_FOLDER ="uploads"
os.makedirs(UPLOAD_FOLDER,exist_ok=True)#checks to make sure the local device file uploads from a real directory
File_Size_Cap=50 *1024*1024  #variable that holds the max size of file which is 50mb.
ENCRYPTION_KEY= secrets.token_bytes(32)  # 256-bit AES key
app.config["UPLOAD_FOLDER"]=UPLOAD_FOLDER
def encrypt_file(file_data):#use aes256 to encrypt file to keep secure
    iv= secrets.token_bytes(16)  # Generate a random IV
    cipher= AES.new(ENCRYPTION_KEY, AES.MODE_CBC, iv)
    pad_len=16- (len(file_data) %16)
    file_data+= bytes([pad_len]) * pad_len
    encrypted_data = cipher.encrypt(file_data)
    return iv+encrypted_data  # Prepend IV for decryption
def compute_checksum(file_data):#helper to get checksum value
    return hashlib.sha256(file_data).hexdigest()
@app.route('/upload_file',methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error":"No file provided"}),400
    file=request.files['file']
    recipient=request.form.get("recipient")
    if not recipient:
        return jsonify({"error": "needs to be the recipient"}),400
    if file.filename == '':
        return jsonify({"error": "no file was selected"}), 400
    if file and file.content_length >File_Size_Cap:
        return jsonify({"error": "The file size is greater than the 50MB limit"}),400
    filename= secure_filename(file.filename)
    file_data=file.read()
    encrypted_data =encrypt_file(file_data)
    checksum =compute_checksum(encrypted_data)
    file_path=os.path.join(app.config['UPLOAD_FOLDER'],filename)
    with open(file_path,'wb') as f:
        f.write(encrypted_data)
    file_entry={#storing file information in array and then store it in db
        "sender": user["username"],
        "recipient": recipient,
        "filename":filename,
        "checksum":checksum,
        "file_path":file_path}
    db["files"].insert_one(file_entry)#insert to db
    return jsonify({"message": "file uploaded"}), 200
@app.route('/download_file/<filename>', methods=['GET'])
def download_file(filename):
    file_entry= db["files"].find_one({"filename": filename})
    if not file_entry:
        return jsonify({"error": "file was not found"}), 404
    file_path= file_entry["file_path"]
    with open(file_path, 'rb') as f:
        file_data =f.read()
    stored_checksum= file_entry["checksum"]#verify file entry using checksums
    computed_checksum= compute_checksum(file_data)
    if stored_checksum!=computed_checksum:
        return jsonify({"error": "File Integrity vulnerable"}), 500
    return send_file(file_path, as_attachment=True,download_name=filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=2000)
