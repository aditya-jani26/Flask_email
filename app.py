import random
import string
from flask_restful import Api, Resource, reqparse
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from flask import Flask, request, session
import os


app = Flask(__name__)


# setting code for mail
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Users.db'  
app.config['SECRET_KEY'] = 'y7gtt7uasdadasdasdqwebhnftiu'
app.config['MAIL_SERVER'] = 'smtp.gmail.com' 
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'adiyudiz718@gmail.com'
app.config['MAIL_PASSWORD'] = 'qebw bjoo yrgg xjpv'
app.config['MAIL_DEFAULT_SENDER'] = 'adiyudiz718@gmail.com'


db = SQLAlchemy(app)
mail = Mail(app)
jwt = JWTManager(app)
api = Api(app)

# this is db tabe which will store the data

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    
with app.app_context():
    db.create_all()
    

# =============================-Register-====================================

class Register(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')
        
        user = Users.query.filter_by(username=username).first()
        if user:
            return {'message': 'User already exists'}, 400

        user = Users(email=email, username=username, password=password)
        db.session.add(user)
        db.session.commit()
        return {'message': 'User created successfully'}, 201

#===============================-Login-=================================

class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        user = Users.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            return {'message': 'Invalid credentials'}, 401

        access_token = create_access_token(identity=username)
        return {'access_token': access_token}, 200

# ===============================-Logout-==================================
blacklist = set()
@app.route('/logout')
class Logout(Resource):
    @jwt_required
    def post(self):
        
        blacklist.add()
        return {'message': 'Successfully logged out'}, 200
    
# 
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in blacklist

def generate_password_reset_token(user):
    return generate_password_hash(user.username)

# ============================-ForgotPassword-=====================================
parser = reqparse.RequestParser()
parser.add_argument('email', type=str, required=True, help='Email is required')
parser.add_argument('password', type=str)

class ForgotPassword(Resource):
    # @staticmethod
    def post(self):        
        args = parser.parse_args()
        email = args['email']

        user = Users.query.filter_by(email=email).first()
        if user:
            # Generate a random password
            new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
            user.password = generate_password_hash(new_password)  # Update user's password
            db.session.commit()

            # Send email with the new password
            msg = Message('Password Reset', recipients=[email])
            msg.body = f'Your new password is: {new_password}'
            mail.send(msg)

            return {'message': 'Password reset instructions sent to your email'}, 200
        else:
            return {'message': 'Email not found'}, 404


# api.add_resource(index,"/")
api.add_resource(Register, '/register')
api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')
api.add_resource(ForgotPassword, '/forgot-password')

if __name__ == '__main__':
    app.run(debug=True)
# This command will not create the unnassery code: . env: PYTHONDONTWRITEBYTECODE =1