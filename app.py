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
from collections import defaultdict
from time import time
from dotenv import load_dotenv
import os
import hmac
import hashlib

load_dotenv()
MESSAGEAUTH = os.getenv('SECRET_KEY')

app = Flask(__name__)


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
        
        #let user know whats wrong
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


#helper functions
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
                hmac_hash = hmac.new(MESSAGEAUTH.encode('utf-8'), message.encode('utf-8'), hashlib.sha256).hexdigest()

                # Save message and HMAC hash into database
                stored_message = {
                    "sender": username,
                    "recipient": recipient,
                    "message": message,
                    "hmac": hmac_hash  # Store the HMAC hash with the message
                }

                add_message = message_collection.insert_one(stored_message)
                stored_message["_id"] = str(add_message.inserted_id)

                return jsonify(stored_message)




@app.route('/get_messages', methods=['GET'])
def get_messages():
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

                # Verify the HMAC for message integrity
                received_hmac = message.get('hmac')
                if received_hmac:
                    # Recalculate the HMAC for the message
                    recalculated_hmac = hmac.new(MESSAGEAUTH.encode('utf-8'), message['message'].encode('utf-8'), hashlib.sha256).hexdigest()

                    # If the HMACs don't match, the message has been tampered with
                    if received_hmac != recalculated_hmac:
                        message['integrity_verified'] = False
                    else:
                        message['integrity_verified'] = True
                else:
                    message['integrity_verified'] = False  # If no HMAC exists, integrity check fails

            return jsonify({'messages': messages, 'username': username})
        else:
            return jsonify({"error": "User records not found"}), 404
    else:
        return jsonify({"error": "Authtoken not found"}), 401

    
@app.after_request
def set_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=2000)