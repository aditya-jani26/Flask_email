from flask import Flask, request, jsonify, session
from flask_restful import Api, Resource
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message

app = Flask(__name__)
jwt = JWTManager(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Users.db'  
app.secret_key = 'y7gtt7uftiu'

mail = Mail(app)

api = Api(app)
db = SQLAlchemy(app)


app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'adiyudiz718@gmail.com'
app.config['MAIL_PASSWORD'] = '6353yudiz592494hellO'





class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    
# with app.app_context():
#     db.create_all()

class Register(Resource):
    def post(self):
        
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')
        user = Users.query.filter_by(username=username).first()
        if user:
            return {'message': 'User already exists'}, 400

        user = Users(email=email,username=username, password=password)
        db.session.add(user)
        db.session.commit()
        return {'message': 'User created successfully'}, 201

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


blacklist = set()

class Logout(Resource):
    @jwt_required
    def post(self):
        
        blacklist.add()
        return {'message': 'Successfully logged out'}, 200
    

def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in blacklist

def generate_password_reset_token(user):
    return generate_password_hash(user.username)

class ForgotPassword(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')

        user = Users.query.filter_by(username=username).first()

        if not user:
            return {'message': 'User does not exist'}, 404

        # Generate a token for password reset (You can use any method you prefer)
        reset_token = generate_password_reset_token(user)

        # Send the password reset link via email
        send_password_reset_email(user.email, reset_token)

        return {'message': 'Password reset instructions sent to email'}, 200
    
def send_password_reset_email(email, reset_token):

    msg = Message('Password Reset Request', recipients=[email])

    # Replace `example.com` with your actual domain name

    reset_link = f'http://adiyudiz718@gmail.com/reset-password?token={reset_token}'
    msg.body = f'Click the following link to reset your password: {reset_link}'
 
    # Send the email
    Mail.send(msg)

api.add_resource(Register, '/register')
api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')
api.add_resource(ForgotPassword, '/forgot-password')

app.run(debug=True)

if __name__ == '__main__':
    app.run(debug=True)
