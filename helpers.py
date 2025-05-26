# Añadir estos imports al inicio del archivo
from sqlalchemy import and_, or_

# Modelos adicionales
class NotaCompartida(db.Model):
    __tablename__ = 'notas_compartidas'
    id = db.Column(db.Integer, primary_key=True)
    nota_id = db.Column(db.Integer, db.ForeignKey('notas.id', ondelete='CASCADE'), nullable=False)
    psicologo_id = db.Column(db.Integer, db.ForeignKey('psicologos.id', ondelete='CASCADE'), nullable=False)
    clave_sesion_cifrada = db.Column(db.Text, nullable=False)
    nonce = db.Column(db.Text, nullable=False)
    tag = db.Column(db.Text, nullable=False)
    fecha_compartida = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    puede_editar = db.Column(db.Boolean, default=False)

# Modificar el modelo Nota para incluir los nuevos campos
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
    es_compartida = db.Column(db.Boolean, default=False)
    propietario_id = db.Column(db.Integer, db.ForeignKey('psicologos.id'))

# Nuevas rutas de la API
@app.route('/compartir-nota', methods=['POST'])
def compartir_nota():
    if 'psicologo_id' not in session or not session['logged_in']:
        return jsonify({'error': 'No autorizado'}), 401
    
    data = request.get_json()
    nota_id = data.get('nota_id')
    psicologos_compartir = data.get('psicologos')  # Lista de {'id': X, 'puede_editar': bool}
    clave_publica_autor = data.get('clave_publica_autor')
    
    if not nota_id or not psicologos_compartir or not clave_publica_publica_autor:
        return jsonify({'error': 'Faltan campos requeridos'}), 400
    
    # Verificar que la nota existe y pertenece al psicólogo
    nota = Nota.query.filter_by(id=nota_id, psicologo_id=session['psicologo_id']).first()
    if not nota:
        return jsonify({'error': 'Nota no encontrada o no tienes permisos'}), 404
    
    # Obtener la clave privada del autor
    psicologo_autor = Psicologo.query.get(session['psicologo_id'])
    clave_ecc_autor = ClaveECC.query.filter_by(psicologo_id=psicologo_autor.id).first()
    
    # Derivar clave maestra para descifrar la clave privada ECC del autor
    clave_maestra = derivar_clave(data.get('password'), psicologo_autor.salt)
    
    try:
        private_key_autor = descifrar_clave_privada_ecc(
            base64.b64decode(clave_ecc_autor.clave_privada_cifrada),
            clave_maestra,
            base64.b64decode(clave_ecc_autor.nonce),
            base64.b64decode(clave_ecc_autor.tag)
        )
    except:
        return jsonify({'error': 'Error al descifrar la clave privada. Contraseña incorrecta.'}), 401
    
    # Cargar clave pública del autor (para verificación)
    try:
        peer_public_key_autor = serialization.load_pem_public_key(
            clave_publica_autor.encode('utf-8'),
            backend=default_backend()
        )
    except:
        return jsonify({'error': 'Clave pública del autor inválida'}), 400
    
    # Verificar que la clave pública coincide con la privada
    if private_key_autor.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8') != clave_publica_autor:
        return jsonify({'error': 'Clave pública no coincide con la privada'}), 400
    
    # Derivar clave de sesión original (para descifrar la nota)
    clave_sesion_original = derivar_clave_sesion(private_key_autor, peer_public_key_autor)
    
    # Descifrar la nota para obtener el contenido original
    try:
        contenido_original = descifrar_contenido(
            base64.b64decode(nota.contenido_cifrado),
            clave_sesion_original,
            base64.b64decode(nota.nonce),
            base64.b64decode(nota.tag)
        )
    except:
        return jsonify({'error': 'Error al descifrar la nota original'}), 400
    
    # Marcar la nota como compartida
    nota.es_compartida = True
    nota.propietario_id = session['psicologo_id']
    db.session.commit()
    
    resultados = []
    
    for psicologo_data in psicologos_compartir:
        psicologo_id = psicologo_data.get('id')
        puede_editar = psicologo_data.get('puede_editar', False)
        
        # Obtener la clave pública del psicólogo con quien se compartirá
        psicologo_destino = Psicologo.query.get(psicologo_id)
        if not psicologo_destino:
            continue
        
        clave_ecc_destino = ClaveECC.query.filter_by(psicologo_id=psicologo_destino.id).first()
        if not clave_ecc_destino:
            continue
        
        # Cargar clave pública del destino
        try:
            public_key_destino = serialization.load_pem_public_key(
                clave_ecc_destino.clave_publica.encode('utf-8'),
                backend=default_backend()
            )
        except:
            continue
        
        # Generar una nueva clave de sesión para esta relación
        nueva_clave_sesion = os.urandom(32)
        
        # Cifrar la nueva clave de sesión con ECDH
        shared_key = private_key_autor.exchange(ec.ECDH(), public_key_destino)
        
        # Derivar una clave para cifrar la clave de sesión
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'nota_compartida',
            backend=default_backend()
        )
        clave_cifrado_sesion = hkdf.derive(shared_key)
        
        # Cifrar la clave de sesión con AES-GCM
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(clave_cifrado_sesion), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        clave_sesion_cifrada = encryptor.update(nueva_clave_sesion) + encryptor.finalize()
        
        # Guardar la relación de nota compartida
        nueva_nota_compartida = NotaCompartida(
            nota_id=nota.id,
            psicologo_id=psicologo_destino.id,
            clave_sesion_cifrada=base64.b64encode(clave_sesion_cifrada).decode('utf-8'),
            nonce=base64.b64encode(nonce).decode('utf-8'),
            tag=base64.b64encode(encryptor.tag).decode('utf-8'),
            puede_editar=puede_editar
        )
        db.session.add(nueva_nota_compartida)
        
        # Volver a cifrar el contenido con la nueva clave de sesión
        encrypted_data = cifrar_contenido(contenido_original, nueva_clave_sesion)
        
        # Actualizar la nota con el nuevo cifrado (si el primer psicólogo puede editar)
        if puede_editar:
            nota.contenido_cifrado = encrypted_data['contenido_cifrado']
            nota.nonce = encrypted_data['nonce']
            nota.tag = encrypted_data['tag']
        
        resultados.append({
            'psicologo_id': psicologo_destino.id,
            'email': psicologo_destino.email,
            'compartido': True,
            'puede_editar': puede_editar
        })
    
    db.session.commit()
    
    return jsonify({
        'mensaje': 'Nota compartida exitosamente',
        'resultados': resultados
    }), 200

@app.route('/notas-compartidas', methods=['GET'])
def obtener_notas_compartidas():
    if 'psicologo_id' not in session or not session['logged_in']:
        return jsonify({'error': 'No autorizado'}), 401
    
    # Notas que el psicólogo ha creado y compartido
    notas_como_propietario = Nota.query.filter_by(
        propietario_id=session['psicologo_id'],
        es_compartida=True
    ).all()
    
    # Notas que otros han compartido con este psicólogo
    notas_compartidas_conmigo = db.session.query(Nota).join(
        NotaCompartida,
        NotaCompartida.nota_id == Nota.id
    ).filter(
        NotaCompartida.psicologo_id == session['psicologo_id']
    ).all()
    
    # Preparar respuesta
    respuesta = {
        'como_propietario': [],
        'compartidas_conmigo': []
    }
    
    for nota in notas_como_propietario:
        respuesta['como_propietario'].append({
            'id': nota.id,
            'paciente_id': nota.paciente_id,
            'fecha_creacion': nota.fecha_creacion.isoformat(),
            'fecha_actualizacion': nota.fecha_actualizacion.isoformat(),
            'compartida_con': [
                {
                    'psicologo_id': nc.psicologo_id,
                    'puede_editar': nc.puede_editar,
                    'fecha_compartida': nc.fecha_compartida.isoformat()
                }
                for nc in NotaCompartida.query.filter_by(nota_id=nota.id).all()
            ]
        })
    
    for nota in notas_compartidas_conmigo:
        relacion = NotaCompartida.query.filter_by(
            nota_id=nota.id,
            psicologo_id=session['psicologo_id']
        ).first()
        
        respuesta['compartidas_conmigo'].append({
            'id': nota.id,
            'paciente_id': nota.paciente_id,
            'propietario_id': nota.propietario_id,
            'fecha_creacion': nota.fecha_creacion.isoformat(),
            'fecha_actualizacion': nota.fecha_actualizacion.isoformat(),
            'puede_editar': relacion.puede_editar if relacion else False
        })
    
    return jsonify(respuesta), 200

@app.route('/actualizar-permisos-nota', methods=['POST'])
def actualizar_permisos_nota():
    if 'psicologo_id' not in session or not session['logged_in']:
        return jsonify({'error': 'No autorizado'}), 401
    
    data = request.get_json()
    nota_id = data.get('nota_id')
    cambios = data.get('cambios')  # Lista de {'psicologo_id': X, 'puede_editar': bool}
    
    if not nota_id or not cambios:
        return jsonify({'error': 'Faltan campos requeridos'}), 400
    
    # Verificar que la nota existe y es propiedad del psicólogo
    nota = Nota.query.filter_by(id=nota_id, propietario_id=session['psicologo_id']).first()
    if not nota:
        return jsonify({'error': 'Nota no encontrada o no eres el propietario'}), 404
    
    resultados = []
    
    for cambio in cambios:
        psicologo_id = cambio.get('psicologo_id')
        puede_editar = cambio.get('puede_editar', False)
        
        # Actualizar la relación de nota compartida
        nota_compartida = NotaCompartida.query.filter_by(
            nota_id=nota.id,
            psicologo_id=psicologo_id
        ).first()
        
        if nota_compartida:
            nota_compartida.puede_editar = puede_editar
            resultados.append({
                'psicologo_id': psicologo_id,
                'actualizado': True,
                'puede_editar': puede_editar
            })
        else:
            resultados.append({
                'psicologo_id': psicologo_id,
                'actualizado': False,
                'error': 'Relación no encontrada'
            })
    
    db.session.commit()
    
    return jsonify({
        'mensaje': 'Permisos actualizados',
        'resultados': resultados
    }), 200

@app.route('/obtener-nota-compartida/<int:nota_id>', methods=['POST'])
def obtener_nota_compartida(nota_id):
    if 'psicologo_id' not in session or not session['logged_in']:
        return jsonify({'error': 'No autorizado'}), 401
    
    data = request.get_json()
    clave_publica_cliente = data.get('clave_publica_cliente')
    
    if not clave_publica_cliente:
        return jsonify({'error': 'Falta la clave pública del cliente'}), 400
    
    # Verificar que el psicólogo tiene acceso a la nota
    nota = Nota.query.get(nota_id)
    if not nota:
        return jsonify({'error': 'Nota no encontrada'}), 404
    
    # Verificar si es el propietario o tiene acceso compartido
    relacion = None
    if nota.propietario_id == session['psicologo_id']:
        # Es el propietario
        relacion = NotaCompartida.query.filter_by(
            nota_id=nota.id,
            psicologo_id=session['psicologo_id']
        ).first()
    else:
        # Verificar si está en la lista de compartidos
        relacion = NotaCompartida.query.filter_by(
            nota_id=nota.id,
            psicologo_id=session['psicologo_id']
        ).first()
    
    if not relacion and nota.propietario_id != session['psicologo_id']:
        return jsonify({'error': 'No tienes acceso a esta nota'}), 403
    
    # Obtener la clave privada del psicólogo actual
    psicologo_actual = Psicologo.query.get(session['psicologo_id'])
    clave_ecc_actual = ClaveECC.query.filter_by(psicologo_id=psicologo_actual.id).first()
    
    # Derivar clave maestra para descifrar la clave privada ECC
    clave_maestra = derivar_clave(data.get('password'), psicologo_actual.salt)
    
    try:
        private_key_actual = descifrar_clave_privada_ecc(
            base64.b64decode(clave_ecc_actual.clave_privada_cifrada),
            clave_maestra,
            base64.b64decode(clave_ecc_actual.nonce),
            base64.b64decode(clave_ecc_actual.tag)
        )
    except:
        return jsonify({'error': 'Error al descifrar la clave privada. Contraseña incorrecta.'}), 401
    
    # Cargar clave pública del propietario (para ECDH)
    psicologo_propietario = Psicologo.query.get(nota.propietario_id)
    clave_ecc_propietario = ClaveECC.query.filter_by(psicologo_id=psicologo_propietario.id).first()
    
    try:
        public_key_propietario = serialization.load_pem_public_key(
            clave_ecc_propietario.clave_publica.encode('utf-8'),
            backend=default_backend()
        )
    except:
        return jsonify({'error': 'Error al cargar la clave pública del propietario'}), 500
    
    # Derivar clave compartida para descifrar la clave de sesión
    shared_key = private_key_actual.exchange(ec.ECDH(), public_key_propietario)
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'nota_compartida',
        backend=default_backend()
    )
    clave_cifrado_sesion = hkdf.derive(shared_key)
    
    # Descifrar la clave de sesión
    try:
        cipher = Cipher(
            algorithms.AES(clave_cifrado_sesion),
            modes.GCM(
                base64.b64decode(relacion.nonce),
                base64.b64decode(relacion.tag)
            ),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        clave_sesion = decryptor.update(base64.b64decode(relacion.clave_sesion_cifrada)) + decryptor.finalize()
    except:
        return jsonify({'error': 'Error al descifrar la clave de sesión'}), 400
    
    # Descifrar el contenido de la nota
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
        'paciente_id': nota.paciente_id,
        'propietario_id': nota.propietario_id,
        'puede_editar': relacion.puede_editar if relacion else True
    }), 200
