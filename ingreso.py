# Librerias que usuara la app
from flask import Flask, request, jsonify
import sqlite3
import random
import re
import bcrypt

# Identificador de Flask
app = Flask(__name__)

# Conexion con la base de datos.
def conexion_db():
    conn = sqlite3.connect(r"TU_BASE_DB")
    conn.row_factory = sqlite3.Row
    return conn

# Ruta para registrar al usuario.
@app.route("/registrer", methods = ["POST"])
def registro_user():
    try:
        # Conversion a un archivo Json.
        data = request.get_json()

        # Datos del usuario tomados del frontend.
        user_name = data.get("name","").strip()
        user_lastname = data.get("lastname","").strip()
        user_email = data.get("email","").strip()
        user_password = data.get("password","").strip()

        # Verificadores (email,password).
        verificador_email = r"[a-zA-Z-0-9]+@[a-zA-Z]+\.[a-z-.]+$"
        verificador_password = r"^[a-zA-Z0-9@#$%^&+=]{6,}$"

        # Encriptador de password.
        encriptador_password = bcrypt.hashpw(user_password.encode("UTF-8"), bcrypt.gensalt())

        # Verificadores de entrada.
        if not all([user_name,user_lastname,user_email,user_password]):
            return jsonify({"Error": "Todos los campos deben estar completos"}),400
        if not re.fullmatch(verificador_email, user_email):
            return jsonify({"Error": "Correo invalido"}),400
        if not re.fullmatch(verificador_password, user_password):
            return jsonify({"Error": "La contraseña debe tener al menos 6 caracteres"}), 400

        #Conexiones y peticiones a la base de datos.
        conn = conexion_db()
        cursor = conn.cursor()
        cursor.execute("""
                    INSERT INTO usuario(user_name,user_lastname,user_email,user_password) VALUES (?,?,?,?)
                    """,(user_name,user_lastname,user_email,encriptador_password))
        conn.commit()
        conn.close()
        return jsonify({"mensaje": "Usuario registrado con exito."}),201

    # Manejo de errores.
    except sqlite3.IntegrityError:
        return jsonify({"error": "El usuario ya existe"}),400

    except Exception as error:
        return jsonify({"error": f"Ocurrio un error inesperado: {str(error)}"}),500
        