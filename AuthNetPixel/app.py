# app.py
from flask import Flask, jsonify, request, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_restful import Api, Resource
from models import db, User
from flask_migrate import Migrate
from config import Config
import pyotp
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import ssl
import re


# Inicialização do Flask e extensões
app = Flask(__name__)

app.config.from_object(Config)  # Configurações do Flask

# Configurando CORS
CORS(app, supports_credentials=True, resources={r"*": {"origins": "http://localhost:8100"}})

bcrypt = Bcrypt(app)

# Inicializa o banco de dados
app.config['SESSION_TYPE'] = 'filesystem'
db.init_app(app)
app.config['SECRET_KEY'] = 'MYSECRETKEY32'
app.config["JWT_SECRET_KEY"] = 'SECRETJWT32'
app.config['JWT_TOKEN_LOCATION'] = ['headers']

jwt = JWTManager(app)


secret_key = pyotp.random_base32()
totp = pyotp.TOTP(secret_key, interval=30)

# rota para validar um token. 
@app.route('/validate-token', methods=['GET'])
@jwt_required()
def validate_token():
    try:
        current_user = get_jwt_identity()
        return jsonify({"valid": True, "user": current_user}), 200
    except Exception as e:
        return jsonify({"valid": False, "error": str(e)}), 401
# Rota que gera um OTP
@app.route("/generate-otp", methods=['GET', 'POST'])
@jwt_required()

def generate_otp():

    user_id = get_jwt_identity()  

    if not user_id:
        return jsonify({"valid": False, "error": "JWT inválido ou ausente."}), 401
    else:
        try: 
            
           
            otp = totp.now()
            
            return jsonify({"otp": otp, "message": "Código OTP gerado com sucesso."}), 200
        except Exception as e:
            return jsonify({"valid": False, "error": str(e)}), 401

    


@app.route("/verify-otp", methods=['POST'])
def verify_otp():

    
    user_otp = request.json.get('otp')

    otp_validate = totp.verify(user_otp)

    
        
  

    if not user_otp:
        return jsonify({"message": "OTP não fornecido."}), 400

    
    if(otp_validate == True):
        return jsonify({"message": "OTP verificado. Acesso concedido."}), 200
    else:
        return jsonify({"message": "OTP expirado ou inválido. Tente me fornecer um novo"}), 404

class Signup(Resource):
    def post(self):
        username = request.get_json().get('username')
        password = request.get_json().get('password')
        email = request.get_json().get('email')

        email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_regex, email):
            return {'error': 'E-mail inválido.'}, 400

     
        if len(password) <= 5:
            return {'error': 'A senha deve ter pelo menos 6 caracteres e um caracter especial.'}, 400

        if not any(char in "!@#$%^&*()-_=+[]{}|;:',.<>?/`~" for char in password):
            return {'error': 'A senha deve conter pelo menos um caractere especial.'}, 400
        

      

        if username and password and email:
            existing_email = User.query.filter_by(email=email).first()
            if existing_email:
                return {'error': 'E-mail já cadastrado.'}, 409  # Conflito

            # Criação correta do usuário
            new_user = User(username=username, email=email)
            new_user.password_hash = password

            db.session.add(new_user)
            db.session.commit()

            session['user_id'] = new_user.id
            
            return new_user.to_dict(), 201

        return {'error': '422 Unprocessable Entity'}, 422



class Login(Resource):
    def post(self):
        
        email = request.get_json().get('email')
        password = request.get_json().get('password')
        if not email or not password:
            return {'error': 'Email de usuário e senha são obrigatórios.'}, 400

        user = User.query.filter_by(email=email).first()

        if user and user.authenticate(password):
            access_token = create_access_token(identity=user.id)
            print(f"Usuário autenticado. token: {access_token}")  
            return jsonify({"access_token": access_token})
                
        return {'error': 'Email ou senha inválidos.'}, 401



# Inicializa a API
api = Api(app)
migrate = Migrate(app, db)
api.add_resource(Signup, '/signup')
api.add_resource(Login, '/login')  

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
