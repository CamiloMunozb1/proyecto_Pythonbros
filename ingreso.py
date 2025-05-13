from flask import Flask, request, jsonify
import sqlite3
import random
import re
import bcrypt

app = Flask(__name__)


def conexion_db():
    conn = sqlite3.connect(r"TU_BASE_DB")
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/registrer", methods = ["POST"])
def registro_user():
    try:
        data = request.get_json()

        user_name = data.get("name","").strip()
        user_lastname = data.get("lastname","").strip()
        user_email = data.get("email","").strip()
        user_password = data.get("password","").strip()

        verificador_email = r"[a-zA-Z-0-9]+@[a-zA-Z]+\.[a-z-.]+$"
        verificador_password = r"^[a-zA-Z0-9@#$%^&+=]{6,}$"
        encriptador_password = bcrypt.hashpw(user_password.encode("UTF-8"), bcrypt.gensalt())

        if not all([user_name,user_lastname,user_email,user_password]):
            return jsonify({"Error": "Todos los campos deben estar completos"}),400
        elif re.fullmatch(verificador_email, user_email):
            return jsonify({"Error": "Correo invalido"}),400
        elif re.fullmatch(verificador_password, user_password):
            return jsonify({"Error": "La contraseña debe tener al menos 6 caracteres"}), 400
        
