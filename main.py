from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from jose import jwt


app = FastAPI()


# Diccionario global de usuarios
usuarios = {}


# Clave utilizada para firmar el token
CLAVE_SECRETA = "clave-secreta"
ALGORITMO = "HS256"


# -------------------------
# Modelos de datos
# -------------------------

class Usuario(BaseModel):
    username: str
    password: str
    rol: str


class Login(BaseModel):
    username: str
    password: str


class ModificarRol(BaseModel):
    username: str
    rol: str


class EliminarUsuario(BaseModel):
    username: str


# -------------------------
# Función: registrar usuario
# -------------------------

def registrar_usuario(username, password, rol):

    if username in usuarios:
        return False

    usuarios[username] = {
        "username": username,
        "password": password,
        "rol": rol
    }

    return True


# -------------------------
# Función: autenticar usuario
# -------------------------

def autenticar_usuario(username, password):

    if username not in usuarios:
        return None

    if usuarios[username]["password"] != password:
        return None

    return usuarios[username]


# -------------------------
# Función: modificar rol
# -------------------------

def modificar_rol(username, rol):

    if username not in usuarios:
        return None

    usuarios[username]["rol"] = rol

    return usuarios[username]


# -------------------------
# Función: eliminar usuario
# -------------------------

def eliminar_usuario(username):

    if username not in usuarios:
        return False

    del usuarios[username]

    return True


# -------------------------
# Alta de usuario
# -------------------------

@app.post("/alta_usuario", status_code=201)
def alta_usuario(usuario: Usuario):

    resultado = registrar_usuario(
        usuario.username,
        usuario.password,
        usuario.rol
    )

    if not resultado:
        raise HTTPException(
            status_code=400,
            detail="El usuario ya existe"
        )

    return {
        "mensaje": "Usuario registrado correctamente",
        "usuario": usuario.username
    }


# -------------------------
# Login usuario
# -------------------------

@app.post("/login")
def login(datos: Login):

    usuario = autenticar_usuario(
        datos.username,
        datos.password
    )

    if usuario is None:
        raise HTTPException(
            status_code=401,
            detail="Usuario o contraseña incorrectos"
        )

    datos_token = {
        "username": usuario["username"],
        "rol": usuario["rol"]
    }

    token = jwt.encode(
        datos_token,
        CLAVE_SECRETA,
        algorithm=ALGORITMO
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "rol": usuario["rol"]
    }


# -------------------------
# Modificar rol
# -------------------------

@app.put("/modificar_rol")
def cambiar_rol(datos: ModificarRol):

    usuario = modificar_rol(
        datos.username,
        datos.rol
    )

    if usuario is None:
        raise HTTPException(
            status_code=404,
            detail="Usuario no encontrado"
        )

    return {
        "mensaje": "Rol modificado correctamente",
        "usuario": usuario
    }


# -------------------------
# Eliminar usuario
# -------------------------

@app.delete("/eliminar_usuario")
def borrar_usuario(datos: EliminarUsuario):

    resultado = eliminar_usuario(datos.username)

    if not resultado:
        raise HTTPException(
            status_code=404,
            detail="Usuario no encontrado"
        )

    return {
        "mensaje": "Usuario eliminado correctamente",
        "username": datos.username
    }