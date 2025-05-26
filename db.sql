CREATE TABLE psicologos (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    salt VARCHAR(255) NOT NULL,
    nombre VARCHAR(100) NOT NULL,
    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    activo BOOLEAN DEFAULT TRUE
);

CREATE TABLE pacientes (
    id SERIAL PRIMARY KEY,
    psicologo_id INTEGER REFERENCES psicologos(id),
    identificador VARCHAR(100) NOT NULL,  -- Puede ser nombre o código único
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(psicologo_id, identificador)
);

CREATE TABLE claves_ecc (
    psicologo_id INTEGER PRIMARY KEY REFERENCES psicologos(id),
    clave_publica TEXT NOT NULL,
    clave_privada_cifrada TEXT NOT NULL,
    nonce TEXT NOT NULL,
    tag TEXT NOT NULL
);

CREATE TABLE notas (
    id SERIAL PRIMARY KEY,
    psicologo_id INTEGER REFERENCES psicologos(id),
    paciente_id INTEGER REFERENCES pacientes(id),
    contenido_cifrado TEXT NOT NULL,
    nonce TEXT NOT NULL,
    tag TEXT NOT NULL,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    fecha_actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Nueva tabla para almacenar las claves de sesión compartidas
CREATE TABLE notas_compartidas (
    id SERIAL PRIMARY KEY,
    nota_id INTEGER REFERENCES notas(id) ON DELETE CASCADE,
    psicologo_id INTEGER REFERENCES psicologos(id) ON DELETE CASCADE,
    clave_sesion_cifrada TEXT NOT NULL,
    nonce TEXT NOT NULL,
    tag TEXT NOT NULL,
    fecha_compartida TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    puede_editar BOOLEAN DEFAULT FALSE,
    UNIQUE(nota_id, psicologo_id)
);

-- Modificación a la tabla notas para identificar al propietario original
ALTER TABLE notas ADD COLUMN es_compartida BOOLEAN DEFAULT FALSE;
ALTER TABLE notas ADD COLUMN propietario_id INTEGER REFERENCES psicologos(id);
