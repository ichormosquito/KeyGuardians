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
import io
import hmac
from collections import defaultdict
from time import time
from dotenv import load_dotenv
from Crypto.Cipher import AES
from werkzeug.utils import secure_filename
from flask import send_file, make_response


load_dotenv()
MESSAGEAUTH = os.getenv('NEW_SECRET_KEY')

app = Flask(__name__,static_folder='static', static_url_path='/static')

mongo_client = MongoClient("mongodb://mongo:27017/")
db = mongo_client["secureDove"]
usercred_collection = db["credentials"]
message_collection = db["messages"]


#DoS protection
class RateLimiter:
    def __init__(self, max_requests=50, time_window=10, block_duration=300):
        #store request timestamps by IP
        self.request_history = defaultdict(list) 
        #store blocked IPs with block time
        self.blocked_ips = {} 
        #config params
        self.max_requests = max_requests
        self.time_window = time_window
        self.block_duration = block_duration
        print(f"RateLimiter initialized: {max_requests} requests per {time_window}s, block duration: {block_duration}s")
    
    def get_client_ip(self):
        #extract real client IP from headers or remote_addr
        ip = request.headers.get('X-Forwarded-For', 
              request.headers.get('X-Real-IP', request.remote_addr))
        print(f"Client IP detected: {ip}")
        return ip
    
    def is_allowed(self):
        #check if request is allowed based on rate limiting rules
        ip = self.get_client_ip()
        current_time = time()
        
        #check if IP is currently blocked
        if ip in self.blocked_ips:
            #if block duration has passed, unblock the IP
            if current_time - self.blocked_ips[ip] >= self.block_duration:
                print(f"Unblocking IP: {ip} (block duration expired)")
                del self.blocked_ips[ip]
                self.request_history[ip] = []  #clear history for this IP
            else:
                block_time_left = int(self.block_duration - (current_time - self.blocked_ips[ip]))
                print(f"Blocking request from {ip}: still blocked for {block_time_left}s")
                return False  #IP is still blocked
        
        #record this request
        self.request_history[ip].append(current_time)
        
        #remove timestamps older than the time window
        old_count = len(self.request_history[ip])
        self.request_history[ip] = [
            timestamp for timestamp in self.request_history[ip] 
            if current_time - timestamp <= self.time_window
        ]
        new_count = len(self.request_history[ip])
        if old_count != new_count:
            print(f"Cleaned {old_count - new_count} old requests from history for {ip}")
        
        #check if request count exceeds the limit
        request_count = len(self.request_history[ip])
        print(f"Request count for {ip}: {request_count}/{self.max_requests} in last {self.time_window}s")
        
        if request_count > self.max_requests:
            print(f"Rate limit exceeded for {ip}. Blocking for {self.block_duration}s")
            self.blocked_ips[ip] = current_time  #block this IP
            return False
        
        return True

#initialize rate limiter with custom settings
#allow 100 requests per minute, block for 10 minutes if exceeded
rate_limiter = RateLimiter(
    max_requests=100,
    time_window=60,
    block_duration=600
)

#add rate limiting middleware
@app.before_request
def limit_requests():
    #skip rate limiting for static resources if applicable
    if request.path.startswith('/static/'):
        return None
        
    if not rate_limiter.is_allowed():
        print(f"Rate limit response sent: 429 Too Many Requests")
        return "Rate limit exceeded. Please try again later.", 429


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
            hashedtoken = (sha256(str(auth_token).encode('utf-8'))).hexdigest()
            user_in_database = usercred_collection.find_one({"authtoken": hashedtoken})

            if user_in_database:
                username = user_in_database['username']
                data = request.get_json()
                message = data.get('message')
                recipient = data.get('recipient')
                message = html.escape(message)

                if not message or not recipient:
                    return jsonify({"error": "message and recipient required."}), 400
                
                # Check if recipient exists in db
                recipient_user = usercred_collection.find_one({"username": recipient})
                if not recipient_user:
                    return jsonify({"error": "unknown user"}), 400

                # Generate HMAC for the message
                if MESSAGEAUTH:
                    hmac_hash = hmac.new(MESSAGEAUTH.encode('utf-8'), message.encode('utf-8'), hashlib.sha256).hexdigest()
                else:
                    hmac_hash = None

                # Save message into database
                stored_message = {
                    "sender": username,
                    "recipient": recipient,
                    "message": message
                }
                if hmac_hash:
                    stored_message["hmac"] = hmac_hash

                add_message = message_collection.insert_one(stored_message)
                stored_message["_id"] = str(add_message.inserted_id)

                return jsonify(stored_message)

            print("User records not found")
            return jsonify({"error": "User records not found"}), 404
        return jsonify({"error": "Authtoken not found"}), 401

@app.route('/get_messages', methods=['GET'])
def get_messages():
    #find user by authtoken
    auth_token = request.cookies.get('authtoken')
    if auth_token:
        hashedtoken = (sha256(str(auth_token).encode('utf-8'))).hexdigest()
        user_in_database = usercred_collection.find_one({"authtoken": hashedtoken})

        if user_in_database:
            username = user_in_database['username']
            messages = list(message_collection.find({
                '$or': [{'sender': username}, {'recipient': username}]
            }))

            for message in messages:
                message['_id'] = str(message['_id'])  
                if "hmac" in message and MESSAGEAUTH:
                    recalculated_hmac = hmac.new(MESSAGEAUTH.encode('utf-8'), message['message'].encode('utf-8'), hashlib.sha256).hexdigest()
                    if recalculated_hmac != message["hmac"]:
                        message["integrity_verified"] = False
                    else:
                        message["integrity_verified"] = True
                else:
                    message["integrity_verified"] = False

            files=list(db["files"].find({"recipient":username}))#retrieve the files send to the user
            for f in files:#make objectId a string and mark it as a file entry
                f["_id"]= str(f["_id"])
                f["isFile"]= True
            combined=messages+files
            return jsonify({'messages':combined,'username':username})
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

def encrypt_file(file_data):
    iv =secrets.token_bytes(16)#enerate a random IV
    cipher=AES.new(ENCRYPTION_KEY, AES.MODE_CBC,iv)
    pad_len=16-(len(file_data) %16)
    file_data+=bytes([pad_len] * pad_len)  #padding
    encrypted_data=cipher.encrypt(file_data)
    return iv+ encrypted_data

def compute_checksum(file_data):#helper to get checksum value
    return hashlib.sha256(file_data).hexdigest()

@app.route('/upload_file',methods=['POST'])
def upload_file():
    authtoken =request.cookies.get('authtoken')# makes sure the user is authenticated
    if not authtoken:
        return jsonify({"error": "not logged in"}),401
    hashedtoken=sha256(str(authtoken).encode('utf-8')).hexdigest()
    user=usercred_collection.find_one({"authtoken": hashedtoken})
    if not user:
        return jsonify({"error": "user not found"}),404
    if'file' not in request.files:# check to see if a file was selected 
        return jsonify({"error": "no file chosen"}),400
    file =request.files['file']
    recipient= request.form.get("recipient")
    if not recipient:
        return jsonify({"error": "needs to be the recipient"}), 400
    if file.filename =='':
        return jsonify({"error":"no file was selected"}),400
    if file and file.content_length >File_Size_Cap:#size limit
        return jsonify({"error":"File size is greater than 50MB"}), 400
    filename =secure_filename(file.filename)
    file_data=file.read()
    checksum =compute_checksum(file_data)
    encrypted_data=encrypt_file(file_data)
    file_path= os.path.join(app.config['UPLOAD_FOLDER'],filename)
    with open(file_path,'wb') as f:
        f.write(encrypted_data)
    file_entry={"sender":user["username"],"recipient": recipient,
        "filename":filename,"checksum":checksum,"file_path": file_path}
    db["files"].insert_one(file_entry)
    return jsonify({"message": "file uploaded"}),200

def decrypt_file(encrypted_data):
    iv =encrypted_data[:16]#take IV from the first 16 bytes
    cipher=AES.new(ENCRYPTION_KEY,AES.MODE_CBC, iv)
    decrypted_data=cipher.decrypt(encrypted_data[16:])
    pad_len = decrypted_data[-1]
    return decrypted_data[:-pad_len]#take away padding

@app.route('/download_file/<filename>',methods=['GET'])
def download_file(filename):
    file_entry=db["files"].find_one({"filename":filename})
    if not file_entry:
        return jsonify({"error":"file was not found"}),404
    file_path = file_entry["file_path"]
    with open(file_path, 'rb') as f:
        encrypted_data =f.read()
    decrypted_data=decrypt_file(encrypted_data)
    stored_checksum= file_entry["checksum"]
    computed_checksum=compute_checksum(decrypted_data)
    if stored_checksum!=computed_checksum:
        return jsonify({"error": "File Integrity compromised"}),500
    return send_file(io.BytesIO(decrypted_data),as_attachment=True,download_name=filename)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=2000)
