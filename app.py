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


app = Flask(__name__)


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


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=2000)