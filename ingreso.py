# Librerias que usuara la app
from flask import Flask, request, jsonify
import sqlite3
import random
import re
import datetime
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
                    INSERT INTO usuarios(user_name,user_lastname,user_email,user_password,user_number) VALUES (?,?,?,?,?)
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
        cursor.execute("SELECT 1 FROM usuarios WHERE user_number = ?",(user_number,))
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
        cursor.execute("SELECT user_password FROM usuarios WHERE user_email = ?",(user_email,))
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


# Ruta para el perfil del usuario
@app.route("/profile", methods = ["GET"])
def profile():
    try:
        # Autorizacion en el header y Bearer al Correo
        auth = request.headers.get("Authorization")

        if not auth or not auth.startswith("Bearer "):
            return jsonify({"error": "error de autentificacion"}),401
        
        # Extraccion del correo desde el header.
        user_email = auth.replace("Bearer", "").strip()
        
        # Peticion de nombre, apellido, email y numero de usuario a la base de datos.
        conn = conexion_db()
        cursor = conn.cursor()
        cursor.execute("""
                    SELECT * 
                    FROM usuarios
                    WHERE user_email = ?
                    """,(user_email,))
        row = cursor.fetchone()
        conn.close()

        #  Visualizacion de los datos del usuario
        if row:
            perfil = {
                "name": row["user_name"],
                "lastname": row["user_lastname"],
                "email": row["user_email"],
                "number": row["user_number"]
            }
            return jsonify(perfil), 200
        else:
            return jsonify({"error": "usuario no encontrado"}),404
    
    # Manejo de errores
    except Exception as error:
        return jsonify({"error": f"error inesperado: {str(error)}"}),500


@app.route("/mensajeria", methods = ["GET"])
def registo_mensajes():
    try:
        # Autorizacion en el header y Bearer al Correo.
        auth = request.headers.get("Authorization")

        # Validacion de las autorizaciones.
        if not auth or not auth.startswith("Bearer "):
            return jsonify({"error": "error de autentificacion"}),401
        
        # El email mantiene la sesion abierta para mandar los mensajes.
        user_email = auth.replace("Bearer", "").strip()

        # Peticiones a la base de datos.
        conn = conexion_db()
        cursor = conn.cursor()
        cursor.execute("""
                    SELECT reminente_email, mensaje, fecha_envio
                    FROM mensajes
                    WHERE destinatario_email = ?
                """, (user_email,))
        mensajes = cursor.fetchall()
        conn.close()

        # Visualizacion de los mensajes de usuario.
        mensajes_json = [
            {
                "remitente": mensaje[0],
                "mensaje" : mensaje[1],
                "fecha_envio" : mensaje[2],
            }
            # Se busca el mensaje en la base de datos.
            for mensaje in mensajes
        ]
        # Se retorna el mensaje.
        return jsonify(mensajes_json), 200

    # Manejo de errores.
    except sqlite3.Error as error:
        return jsonify({"error" : f"error en la base de datos : {str(error)}."}),500
    except Exception as error:
        return jsonify({"error" : f"error inesperado: {str(error)}"}),500

@app.route("/mensajeria", methods = ["POST"])
def envio_mensaje():
    try:
        # Autorizacion en el header y bearer.
        auth = request.headers.get("Authorization")

        # Validacion de las autorizaciones.
        if not auth or not auth.startswith("Bearer "):
            return jsonify({"error" : "error de autentificacion."}),401
        
        # Se usa el email registrado por el remitente.
        remitente_email = auth.replace("Bearer", "").strip()

        # Se contruye un archivo en formato JSON para el destinatario y mensaje.
        data = request.get_json()
        destinatario_email = data.get("destinatario")
        mensaje = data.get("mensaje")

        # Se valida que el destinatario y mensaje si existan.
        if not destinatario_email or not mensaje:
            return jsonify({"error" : "destinatario y mensaje requeridos."}),400
        
        # Revision que el destinatario si este registrado en la base de datos.
        conn = conexion_db()
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM usuarios WHERE user_email = ?",(destinatario_email,))
        if cursor.fetchone() is None:
            return jsonify({"error" : "El destinatario no existe."}),404
        
        # Fecha del envio.
        fecha_envio = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Peticiones a la base de datos, donde se guardara y mandara el mensaje.
        conn = conexion_db()
        cursor = conn.cursor()
        cursor.execute("""
                    INSERT INTO mensajes(remitente_email, destinatario_email, mensaje, fecha_envio) VALUES (?,?,?,?)
                """,(remitente_email, destinatario_email, mensaje, fecha_envio))
        conn.commit()
        conn.close()
        return jsonify({"mensaje": "Mensaje enviado corrextamente"}),201
    
    # Manejo de errores.
    except sqlite3.Error as error:
        return jsonify({"error" : f"Error en la base de datos: {str(error)}."})
    except Exception as error:
        return jsonify({"error" : f"Error en el programa {str(error)}"})
