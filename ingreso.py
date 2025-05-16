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
@app.route("/register", methods = ["POST"])
def registro_user():
    try:
        # Conversion a un archivo Json.
        data = request.get_json()

        # Datos del usuario tomados del frontend.
        user_name = data.get("name","").strip()
        user_lastname = data.get("lastname","").strip()
        user_email = data.get("email","").strip()
        user_password = data.get("password","").strip()
        user_number = generar_numero_unico()

        # Verificadores (email,password).
        verificador_email = r"[a-zA-Z-0-9]+@[a-zA-Z]+\.[a-z-.]+$"
        verificador_password = r"^[a-zA-Z0-9@#$%^&+=]{6,}$"

        # Encriptador de password.
        encriptador_password = bcrypt.hashpw(user_password.encode("UTF-8"), bcrypt.gensalt())

        # Verificadores de entrada.
        if not all([user_name,user_lastname,user_email,user_password]):
            return jsonify({"error": "Todos los campos deben estar completos"}),400
        if not re.fullmatch(verificador_email, user_email):
            return jsonify({"error": "Correo invalido"}),400
        if not re.fullmatch(verificador_password, user_password):
            return jsonify({"error": "La contraseña debe tener al menos 6 caracteres"}), 400

        #Conexiones y peticiones a la base de datos.
        conn = conexion_db()
        cursor = conn.cursor()
        cursor.execute("""
                    INSERT INTO usuario(user_name,user_lastname,user_email,user_password,user_number) VALUES (?,?,?,?,?)
                    """,(user_name,user_lastname,user_email,encriptador_password,user_number))
        conn.commit()
        conn.close()
        return jsonify({"mensaje": "Usuario registrado con exito."}),201

    # Manejo de errores.
    except sqlite3.IntegrityError:
        return jsonify({"error": "El usuario ya existe"}),400

    except Exception as error:
        return jsonify({"error": f"Ocurrio un error inesperado: {str(error)}"}),500


def generar_numero_unico():

    # Conexion can base de datos.
    conn = conexion_db()
    cursor = conn.cursor()

    # Inspeccion a la base de datos para no encontrar numeros repetidos.
    while True:
        # Generacion de numeros de 11 digitos aleatorios.
        user_number = ''.join([str(random.randint(0,9))for _ in range(11)])
        # Busqueda de numeros repetidos
        cursor.execute("SELECT 1 FROM usuario WHERE user_number = ?",(user_number,))
        resultado = cursor.fetchone()

        # si el numero no esta se manda el generado a la logica de login.
        if resultado is None:
            conn.close()
            return user_number


# Ruta para el login de usuario.
@app.route("/login", methods = ["POST"])
def login():
    try:
        # Abre el archivo Json.
        data = request.get_json()

        # Ingreso de usuario por medio del email y contraseña registrada.
        user_email = data.get("email", "").strip()
        user_password = data.get("password", "").strip()

        # verificador de email y contraseña.
        verificador_email = r"[a-zA-Z-0-9]+@[a-zA-Z]+\.[a-z-.]+$"
        verificador_password = r"^[a-zA-Z0-9@#$%^&+=]{6,}$"

        # validacion de campos.
        if not user_email or not user_password:
            return jsonify({"error" : "los campos deben estar completos."}),400
        if not re.fullmatch(verificador_email,user_email):
            return jsonify({"error" : "correo invalido"}),400
        if not re.fullmatch(verificador_password, user_password):
            return jsonify({"error" : "contraseña no valida"}),400
        
        # Consulta a la base de usuario.
        conn = conexion_db()
        cursor = conn.cursor()
        cursor.execute("SELECT user_password FROM usuario WHERE user_email",(user_email,))
        row = cursor.fetchone()

        # Busqueda de contraseña hasheada en la tabla.
        if row and bcrypt.checkpw(user_password.encode("utf-8"),row["user_password"]):
            conn.close()
            return jsonify({"mensaje":"login exitoso."}),200
        else:
            conn.close()
            return jsonify({"error":"usuario no encontrado"}),401
    
    # Manejo de errores.
    except sqlite3.Error as error:
        return jsonify({"error" : f"error inesperado en la base de datos {str(error)}"}),500
    except Exception as error:
        return jsonify({"error": f"error inesperado {str(error)}"}),500


