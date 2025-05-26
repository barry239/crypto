from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import base64
import os
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import binascii

app = Flask(__name__)
app.config['SECRET_KEY'] = 'tu_clave_secreta_muy_segura_aqui'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://usuario:contraseña@localhost/nombre_bd'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Modelos
class Psicologo(db.Model):
    __tablename__ = 'psicologos'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    salt = db.Column(db.String(255), nullable=False)
    nombre = db.Column(db.String(100), nullable=False)
    fecha_registro = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    activo = db.Column(db.Boolean, default=True)

class Paciente(db.Model):
    __tablename__ = 'pacientes'
    id = db.Column(db.Integer, primary_key=True)
    psicologo_id = db.Column(db.Integer, db.ForeignKey('psicologos.id'), nullable=False)
    identificador = db.Column(db.String(100), nullable=False)
    fecha_creacion = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())

class ClaveECC(db.Model):
    __tablename__ = 'claves_ecc'
    psicologo_id = db.Column(db.Integer, db.ForeignKey('psicologos.id'), primary_key=True)
    clave_publica = db.Column(db.Text, nullable=False)
    clave_privada_cifrada = db.Column(db.Text, nullable=False)
    nonce = db.Column(db.Text, nullable=False)
    tag = db.Column(db.Text, nullable=False)

class Nota(db.Model):
    __tablename__ = 'notas'
    id = db.Column(db.Integer, primary_key=True)
    psicologo_id = db.Column(db.Integer, db.ForeignKey('psicologos.id'), nullable=False)
    paciente_id = db.Column(db.Integer, db.ForeignKey('pacientes.id'), nullable=False)
    contenido_cifrado = db.Column(db.Text, nullable=False)
    nonce = db.Column(db.Text, nullable=False)
    tag = db.Column(db.Text, nullable=False)
    fecha_creacion = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    fecha_actualizacion = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

# Funciones de ayuda criptográficas
def generar_salt():
    return secrets.token_hex(16)

def derivar_clave(password, salt):
    salt_bytes = salt.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_bytes,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def generar_par_claves_ecc():
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def serializar_clave_publica(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

def cifrar_clave_privada_ecc(private_key, clave_maestra):
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(clave_maestra), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(private_key_bytes) + encryptor.finalize()
    
    return {
        'encrypted_key': base64.b64encode(encrypted_data).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'tag': base64.b64encode(encryptor.tag).decode('utf-8')
    }

def descifrar_clave_privada_ecc(encrypted_data, clave_maestra, nonce, tag):
    cipher = Cipher(algorithms.AES(clave_maestra), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    return serialization.load_pem_private_key(
        decrypted_data,
        password=None,
        backend=default_backend()
    )

def derivar_clave_sesion(private_key, peer_public_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None,
        backend=default_backend()
    ).derive(shared_key)

def cifrar_contenido(contenido, clave_sesion):
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(clave_sesion), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(contenido.encode('utf-8')) + encryptor.finalize()
    
    return {
        'contenido_cifrado': base64.b64encode(encrypted_data).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'tag': base64.b64encode(encryptor.tag).decode('utf-8')
    }

def descifrar_contenido(contenido_cifrado, clave_sesion, nonce, tag):
    cipher = Cipher(algorithms.AES(clave_sesion), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(contenido_cifrado) + decryptor.finalize()
    
    return decrypted_data.decode('utf-8')

# Rutas de la API
@app.route('/registro', methods=['POST'])
def registro():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    nombre = data.get('nombre')
    
    if not email or not password or not nombre:
        return jsonify({'error': 'Faltan campos requeridos'}), 400
    
    if Psicologo.query.filter_by(email=email).first():
        return jsonify({'error': 'El email ya está registrado'}), 400
    
    salt = generar_salt()
    clave_maestra = derivar_clave(password, salt)
    password_hash = generate_password_hash(password)
    
    # Generar par de claves ECC
    private_key, public_key = generar_par_claves_ecc()
    
    # Cifrar clave privada ECC con la clave maestra derivada de la contraseña
    encrypted_private_key = cifrar_clave_privada_ecc(private_key, clave_maestra)
    
    # Guardar psicólogo en la base de datos
    nuevo_psicologo = Psicologo(
        email=email,
        password_hash=password_hash,
        salt=salt,
        nombre=nombre
    )
    db.session.add(nuevo_psicologo)
    db.session.commit()
    
    # Guardar claves ECC
    clave_ecc = ClaveECC(
        psicologo_id=nuevo_psicologo.id,
        clave_publica=serializar_clave_publica(public_key),
        clave_privada_cifrada=encrypted_private_key['encrypted_key'],
        nonce=encrypted_private_key['nonce'],
        tag=encrypted_private_key['tag']
    )
    db.session.add(clave_ecc)
    db.session.commit()
    
    return jsonify({'mensaje': 'Registro exitoso'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'error': 'Faltan campos requeridos'}), 400
    
    psicologo = Psicologo.query.filter_by(email=email).first()
    
    if not psicologo or not check_password_hash(psicologo.password_hash, password):
        return jsonify({'error': 'Credenciales inválidas'}), 401
    
    # Generar clave de sesión temporal para el cliente
    session['psicologo_id'] = psicologo.id
    session['logged_in'] = True
    
    # Devolver la clave pública del servidor (podría ser diferente para cada sesión)
    clave_ecc = ClaveECC.query.filter_by(psicologo_id=psicologo.id).first()
    
    return jsonify({
        'mensaje': 'Login exitoso',
        'clave_publica_servidor': clave_ecc.clave_publica,
        'psicologo_id': psicologo.id,
        'nombre': psicologo.nombre
    }), 200

@app.route('/crear-nota', methods=['POST'])
def crear_nota():
    if 'psicologo_id' not in session or not session['logged_in']:
        return jsonify({'error': 'No autorizado'}), 401
    
    data = request.get_json()
    paciente_id = data.get('paciente_id')
    contenido = data.get('contenido')
    clave_publica_cliente = data.get('clave_publica_cliente')
    
    if not paciente_id or not contenido or not clave_publica_cliente:
        return jsonify({'error': 'Faltan campos requeridos'}), 400
    
    # Verificar que el paciente pertenezca al psicólogo
    paciente = Paciente.query.filter_by(id=paciente_id, psicologo_id=session['psicologo_id']).first()
    if not paciente:
        return jsonify({'error': 'Paciente no encontrado'}), 404
    
    # Obtener la clave privada del psicólogo
    psicologo = Psicologo.query.get(session['psicologo_id'])
    clave_ecc = ClaveECC.query.filter_by(psicologo_id=psicologo.id).first()
    
    # Derivar clave maestra para descifrar la clave privada ECC
    clave_maestra = derivar_clave(data.get('password'), psicologo.salt)
    
    # Descifrar clave privada ECC
    try:
        private_key = descifrar_clave_privada_ecc(
            base64.b64decode(clave_ecc.clave_privada_cifrada),
            clave_maestra,
            base64.b64decode(clave_ecc.nonce),
            base64.b64decode(clave_ecc.tag)
        )
    except:
        return jsonify({'error': 'Error al descifrar la clave privada. Contraseña incorrecta.'}), 401
    
    # Cargar clave pública del cliente
    try:
        peer_public_key = serialization.load_pem_public_key(
            clave_publica_cliente.encode('utf-8'),
            backend=default_backend()
        )
    except:
        return jsonify({'error': 'Clave pública del cliente inválida'}), 400
    
    # Derivar clave de sesión ECDH
    clave_sesion = derivar_clave_sesion(private_key, peer_public_key)
    
    # Cifrar contenido con AES-GCM
    encrypted_data = cifrar_contenido(contenido, clave_sesion)
    
    # Guardar nota cifrada en la base de datos
    nueva_nota = Nota(
        psicologo_id=session['psicologo_id'],
        paciente_id=paciente_id,
        contenido_cifrado=encrypted_data['contenido_cifrado'],
        nonce=encrypted_data['nonce'],
        tag=encrypted_data['tag']
    )
    db.session.add(nueva_nota)
    db.session.commit()
    
    return jsonify({
        'mensaje': 'Nota creada exitosamente',
        'nota_id': nueva_nota.id
    }), 201

@app.route('/obtener-nota/<int:nota_id>', methods=['POST'])
def obtener_nota(nota_id):
    if 'psicologo_id' not in session or not session['logged_in']:
        return jsonify({'error': 'No autorizado'}), 401
    
    data = request.get_json()
    clave_publica_cliente = data.get('clave_publica_cliente')
    
    if not clave_publica_cliente:
        return jsonify({'error': 'Falta la clave pública del cliente'}), 400
    
    # Obtener la nota
    nota = Nota.query.filter_by(id=nota_id, psicologo_id=session['psicologo_id']).first()
    if not nota:
        return jsonify({'error': 'Nota no encontrada'}), 404
    
    # Obtener la clave privada del psicólogo
    psicologo = Psicologo.query.get(session['psicologo_id'])
    clave_ecc = ClaveECC.query.filter_by(psicologo_id=psicologo.id).first()
    
    # Derivar clave maestra para descifrar la clave privada ECC
    clave_maestra = derivar_clave(data.get('password'), psicologo.salt)
    
    # Descifrar clave privada ECC
    try:
        private_key = descifrar_clave_privada_ecc(
            base64.b64decode(clave_ecc.clave_privada_cifrada),
            clave_maestra,
            base64.b64decode(clave_ecc.nonce),
            base64.b64decode(clave_ecc.tag)
        )
    except:
        return jsonify({'error': 'Error al descifrar la clave privada. Contraseña incorrecta.'}), 401
    
    # Cargar clave pública del cliente
    try:
        peer_public_key = serialization.load_pem_public_key(
            clave_publica_cliente.encode('utf-8'),
            backend=default_backend()
        )
    except:
        return jsonify({'error': 'Clave pública del cliente inválida'}), 400
    
    # Derivar clave de sesión ECDH
    clave_sesion = derivar_clave_sesion(private_key, peer_public_key)
    
    # Descifrar contenido
    try:
        contenido_descifrado = descifrar_contenido(
            base64.b64decode(nota.contenido_cifrado),
            clave_sesion,
            base64.b64decode(nota.nonce),
            base64.b64decode(nota.tag)
        )
    except:
        return jsonify({'error': 'Error al descifrar la nota'}), 400
    
    return jsonify({
        'contenido': contenido_descifrado,
        'fecha_creacion': nota.fecha_creacion.isoformat(),
        'fecha_actualizacion': nota.fecha_actualizacion.isoformat(),
        'paciente_id': nota.paciente_id
    }), 200

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'mensaje': 'Sesión cerrada exitosamente'}), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(ssl_context='adhoc', debug=True)
