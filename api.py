from fastapi import FastAPI, Body, UploadFile
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
import time
import uvicorn
import jwt
import os
from dotenv import load_dotenv
import firebase_admin
from firebase_admin import credentials, firestore
import uuid
import bcrypt
import re
from fastapi import FastAPI, File, UploadFile, HTTPException, Form
from fastapi.responses import JSONResponse, FileResponse
import shutil
import os
import json
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import math
from logger_setup import file_logger, app_logger
from pathlib import Path
from fastapi import FastAPI
import firebase_admin
from firebase_admin import credentials, firestore
import os
from dotenv import load_dotenv
import logging
import qrcode
from fastapi.responses import StreamingResponse
from io import BytesIO

app_logger = logging.getLogger("app_logger")

app_logger.info("Server is starting...")

load_dotenv()

# 🔥 Firebase credentials et app initialisation
cred = credentials.Certificate("firebase.json")
if not firebase_admin._apps:  # Vérifie si Firebase a déjà été initialisé
    firebase_admin.initialize_app(cred)
    app_logger.info("Firebase app initialized")
else:
    app_logger.info("Firebase app already initialized")

# Initialise Firestore client
db = firestore.client()
app_logger.info("Firestore client initialized")

# Configuration du serveur
host_ip = "2a01:cb11:ecc:b300:9dd7:f038:2bc6:b17e"
host_port = 8000
app = FastAPI()

app_logger.info(f"All ok ! Server running on : [{host_ip}]:8000")

# 🔥 Plan et stockage 
STORAGE_PLANS = {
    "free": 15,
    "essential": 50,
    "pro": 200,
}

# 🔥 Liste des domaines autorisés
ALLOWED_ORIGINS = []

# 🔥 Liste des IPs bloquées
BLOCKED_IPS = []

# 🔥 Liste des comptes déjà connectés
ACCOUNT_ALREADY_CONNECT = []

# 🚀 Liste des dossiers système connus (à compléter si nécessaire)
SYSTEM_FOLDERS = {
    "$RECYCLE.BIN",
    "System Volume Information",
    "Config.Msi",
    "Recovery",
    "MSOCache",
    "Documents and Settings",
    "swapfile.sys",
    "pagefile.sys",
    "hiberfil.sys",
}

MAX_STORAGE_SIZE = 50 * 1024 * 1024 * 1024

class MyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        
        clientIp = request.client.host
        referer = request.headers.get("Referer", "Aucun referer trouvé")

        # Si c'est une requête OPTIONS, on répond avec les bons en-têtes CORS
        if request.method == "OPTIONS":
            response = Response(status_code=200)
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
            return response

        # Vérification des IPs et des origines autorisées
        if clientIp in BLOCKED_IPS:
            print("! Une IP bannie a essayé de se reconnecter !")
            return Response("403 Forbidden: IP bloquée", status_code=403)

        if referer in ALLOWED_ORIGINS or clientIp == "127.0.0.1" or clientIp == "http://127.0.0.1:5500":
            response = await call_next(request)
            # Ajouter les en-têtes CORS pour toutes les autres requêtes
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
            return response
        # else:
        #     print("! Une origine non autorisée a essayé de se connecter !")
        #     return Response("403 Forbidden: Origine bloquée", status_code=403)
        
def get_free_space(path):
    try:
        total, used, free = shutil.disk_usage(path)
        return free / (1024 ** 3)
    except FileNotFoundError:
        return None

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Autorise toutes les origines (à sécuriser en prod)
    allow_credentials=True,
    allow_methods=["*"],  # Autorise toutes les méthodes (GET, POST, etc.)
    allow_headers=["*"],  # Autorise tous les headers
)

@app.get("/")
async def read_root(request: Request):
    app_logger.info(f"Root endpoint accessed. From : {request.client.host}. Until : Root page")
    return {"message": "Hello World"}

@app.post("/login")
async def login(request: Request, loginInfos: dict = Body(...)):
    user_email = loginInfos["email"]
    user_password = loginInfos["password"]

    app_logger.info(f"For IP : {request.client.host} : Root endpoint accessed. Until : Login")
    
    collection_name = 'users'
    
    user_ref = db.collection(collection_name).where("email", "==", user_email).limit(1).stream()

    document_id = ""

    user_found = False
    storedHashedPassword = ""

    clientIp = request.client.host

    for doc in user_ref:
        data = doc.to_dict()
        storedHashedPassword = data.get("password")
        user_found = True
        document_id = doc.id
        break  

    if user_found:
        if bcrypt.checkpw(user_password.encode(), storedHashedPassword.encode()):
            ACCOUNT_ALREADY_CONNECT.append(clientIp)
            token = str(uuid.uuid4())

            updateToken = db.collection("users").document(document_id)
    
            updateToken.update({
                "token": token,
                "ip": clientIp
            })

            app_logger.info(f"Account with Email : {user_email} is now connect (Token : {token})")
            return Response(f"200 Connexion réussie : {token}", status_code=200)
        else:
            return Response("401 Mot de passe incorrect", status_code=401)
    else:
        print("Utilisateur non trouvé")
        return Response("404 Utilisateur non trouvé", status_code=404)
    
@app.post("/register")
async def register(request: Request, registerInfos: dict = Body(...)):
    app_logger.info(f"For IP : {request.client.host} : Root endpoint accessed. Until : Register")
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

    register_email = registerInfos["email"]
    register_password = registerInfos["password"]
    register_usage = registerInfos["usage"]
    register_usage_key = registerInfos["key"]

    ALL_REGISTER_KEY = ["abcd"]

    user_id = str(uuid.uuid4())

    if not re.match(email_regex, register_email):
        return Response("403 Forbidden: Adresse mail invalide !", status_code=403)
    
    if len(register_password) < 8:
        return Response("403 Forbidden: Mot de passe invalide (le mot de passe doit faire plus de 8 caractères)!", status_code=403)
    if len(register_password) > 30:
        return Response("403 Le mot de passe doit faire moins de 30 caracteres !", status_code=403)
    
    user_ref = db.collection("users").where("email", "==", register_email).stream()

    has_personnal_account = False

    for user in user_ref:
        user_data = user.to_dict()
        if user_data.get("usage") == "personal":
            has_personnal_account = True

    if has_personnal_account and register_usage == "personnal":
        app_logger.info(f"For ip : {request.client.host} : A personal account already exists with the email {register_email}")
    
    if register_usage == "professional":
        if register_usage_key in ALL_REGISTER_KEY:

            salt = bcrypt.gensalt(rounds=12)
            register_password_hashed = bcrypt.hashpw(register_password.encode(), salt).decode("utf-8")

            users_ref = db.collection("users")

            

            user_data = {
                "id": user_id,
                "email": register_email,
                "password": register_password_hashed, 
                "plan": "free",
                "token": None,
                "usage": "personal",
                "authToken": register_usage_key,
                "ip": "",
                "storage":
                {
                    "space": None,
                    "location": {
                        "main": 
                        {
                            "disk": "",
                            "folder": user_id
                        },
                        "backup": 
                        {
                            "disk": "",
                            "folder": user_id
                        }
                        
                    }
                }
            }

            users_ref.add(user_data)

            return Response("200 : Compte proffesionnel créé avec succès", status_code=200)

    salt = bcrypt.gensalt(rounds=12)
    register_password_hashed = bcrypt.hashpw(register_password.encode(), salt).decode("utf-8")

    users_ref = db.collection("users")

    user_data = {
        "id": user_id,
        "email": register_email,
        "password": register_password_hashed, 
        "plan": "free",
        "token": None,
        "usage": "personal",
        "authToken": register_usage_key,
        "ip": "",
        "storage":
        {
            "space": 15,
            "location": {
                "main": 
                {
                    "disk": "",
                    "folder": user_id
                },
                "backup": 
                {
                    "disk": "",
                    "folder": user_id
                }
                
            }
        },
        "infos": {
            "name": "",
            "family name": "",
        }
    }

    users_ref.add(user_data)
    app_logger.info(f"A new user is now added. Email : {register_email}. Id : {user_id}")

    return Response("200 : Compte personnel créé avec succès", status_code=200)

@app.post("/logout")
async def logout(request: Request, logoutInfos: dict = Body(...)):
    app_logger.info(f"For IP : {request.client.host} : Root endpoint accessed. Until : Logout")
    logout_token = logoutInfos["token"]
    logout_email = logoutInfos["email"]

    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

    doc_id = None
    collection_name = 'users'
    field_to_empty = 'token'


    users_ref = db.collection(collection_name).where('email', '>=', logout_email).where('email', '<=', logout_email + '\uf8ff')

    if not re.match(email_regex, logout_email):
        return Response("403 Forbidden: Adresse mail invalide !", status_code=403)


    for doc in users_ref.stream():    
        doc_id = doc.id
        stored_token = doc.to_dict().get('token')
        break

    if doc_id:
        if stored_token == logout_token:
            doc_ref = db.collection(collection_name).document(doc_id)

            doc_ref.update({
                field_to_empty: None
            })
            
            app_logger.info(f"A user is now logout. Email : {logout_email}. Old Token : {logout_token}")
            return Response("200 Déconnexion réussie", status_code=200)
        else:
            return Response("401 Token invalide", status_code=401)
    else:
        return Response("404 Compte non trouvé", status_code=404)

@app.get("/plans_infos")
async def disponibility(request: Request):
    app_logger.info(f"For IP : {request.client.host} : Root endpoint accessed. Until : Plans Infos")

    with open("config.json", "r") as f:
        file_logger.info(f"From : /plan_info route. File open : config.json. Action(s) : Load JSON")
        data = json.load(f)

    total_free_space = sum(disk["free"] for disk in data["disks"].values())
    total_used_space = sum(disk["used"] for disk in data["disks"].values())

    doc_ref = db.collection('infos').document("plans")

    doc = doc_ref.get()

    data = doc.to_dict()

    free_indisponible = data["free"]["indisponible"]
    essential_indisponible = data["essential"]["indisponible"]
    pro_indisponible = data["pro"]["indisponible"]
    entreprise_indisponible = data["entreprise"]["indisponible"]

    free_bestseller = data["free"]["bestseller"]
    essential_bestseller = data["essential"]["bestseller"]
    pro_bestseller = data["pro"]["bestseller"]
    entreprise_bestseller = data["entreprise"]["bestseller"]



    disponibility_data = {
        "all_free_space": total_free_space,
        "all_used_space": total_used_space,
        "50GB_plan": math.floor(total_free_space / 50),
        "150GB_plan": math.floor(total_free_space / 150),
        "plans": {
            "free": {
                "indisponible": free_indisponible,
                "bestseller": free_bestseller
            },
            "essential": {
                "indisponible": essential_indisponible,
                "bestseller": essential_bestseller
            },
            "pro": {
                "indisponible": pro_indisponible,
                "bestseller": pro_bestseller
            },
            "entreprise": {
                "indisponible": entreprise_indisponible,
                "bestseller": entreprise_bestseller
            }
        }
    }

    app_logger.info(f"Load and send infos about plans.")
    return JSONResponse(content=disponibility_data, status_code=200)

@app.post("/upload")
async def upload_files(request: Request, files: list[UploadFile] = File(...), token: str = Form(...), email: str = Form(...)):
    app_logger.info(f"For IP : {request.client.host} : Root endpoint accessed. Until : Upload File")
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

    if not re.match(email_regex, email):
        return Response("403 Forbidden: Adresse mail invalide !", status_code=403)

    app_logger.info(f"For IP : {request.client.host} : Get user and get info for upload...")

    doc_id = None
    collection_name = 'users'
    users_ref = db.collection(collection_name).where('email', '>=', email).where('email', '<=', email + '\uf8ff')

    for doc in users_ref.stream():    
        doc_id = doc.id
        stored_token = doc.to_dict().get('token')
        location = doc.to_dict().get('storage')
        space_need = location["space"]
        user_id = doc.to_dict().get('id')
        break

    if not doc_id or stored_token != token:
        return Response("401 Token invalide", status_code=401)


    uploaded_files = []
    for file in files:
        uploaded_files.append(file.filename)

    if location["location"]["main"]["disk"] == "":
        app_logger.info(f"For IP : {request.client.host} : First upload detected...")
        with open("config.json", "r") as f:
            file_logger.info(f"From : /plan_info route. File open : config.json. Action(s) : Load JSON")
            data = json.load(f)

        for disk, info in data["disks"].items():
            location = info["location"]
            free_space = data["disks"][disk]["free"]
            if free_space is not None:
                if free_space > space_need:
                    data["disks"][disk]["free"] = free_space - space_need
                    data["disks"][disk]["used"] += space_need
                    file_logger.info(f"From : /upload route. Create folder : {data["disks"][disk]["location"] + user_id}.")
                    os.mkdir(data["disks"][disk]["location"] + user_id)

                    with open("config.json", "w") as f:
                        file_logger.info(f"From : /upload route. File open : config.json. Action(s) : Write JSON")
                        json.dump(data, f, indent=4)

                    doc_ref = db.collection('users').document(doc_id)

                    doc_ref.update({
                        'storage.location.main.disk': disk
                    })
                    break
                else:
                    print(f"Le disque {disk} n'est pas éligible")
            else:
                print(f"Le disque {disk} ({location}) n'a pas pu être trouvé.")
                app_logger.warn(f"The disk {disk} can't be find.")
    
    with open("config.json", "r") as f:
        file_logger.info(f"From : /upload route. File open : config.json. Action(s) : Load JSON")
        data = json.load(f)
    
    uploaded_files = []

    for file in files:
        if "/" in file.filename or "\\" in file.filename:
            file_logger.warning(f"From : /upload route. File upload attempt : {file.filename}. Action(s) : Directory import attempted, forbidden")
            return Response("403 Forbidden: L'importation de dossiers est interdite", status_code=403)

        try:
            file_location = os.path.join(data["disks"][location["location"]["main"]["disk"]]["location"] + user_id, file.filename)
            file_logger.info(f"From : /upload route. File path calculated : {file_location}. Action(s) : Preparing to save file")

            with open(file_location, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)
            file_logger.info(f"From : /upload route. File saved : {file.filename}. Action(s) : File uploaded successfully")

            uploaded_files.append(file.filename)
            file_logger.info(f"From : /upload route. File upload successful : {file.filename}. Total files uploaded : {len(uploaded_files)}")

        except Exception as e:
            file_logger.error(f"From : /upload route. Error uploading file : {file.filename}. Action(s) : {str(e)}")
            return Response(f"Erreur lors de l'importation du fichier {file.filename}: {str(e)}", status_code=500)
        
    app_logger.info(f"All files are uploaded, from {request.client.host}. Account : {email}. Token : {token}")
    return {"uploaded_files": uploaded_files, "message": f"{len(uploaded_files)} fichier(s) importé(s) avec succès."}

@app.post("/delete")
async def delete(request: Request, deleteInfos: dict = Body(...)):
    app_logger.info(f"For IP : {request.client.host} : Root endpoint accessed. Until : Delete File")
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

    email = deleteInfos["email"]
    token = deleteInfos["token"]
    file = deleteInfos["file"]

    if not re.match(email_regex, email):
        return Response("403 Forbidden: Adresse mail invalide !", status_code=403)

    doc_id = None
    collection_name = 'users'
    users_ref = db.collection(collection_name).where('email', '>=', email).where('email', '<=', email + '\uf8ff')

    for doc in users_ref.stream():    
        doc_id = doc.id
        stored_token = doc.to_dict().get('token')
        location = doc.to_dict().get('storage')
        user_id = doc.to_dict().get('id')
        break

    if not doc_id or stored_token != token:
        return Response("401 Token invalide", status_code=401)
    

    with open("config.json", "r") as f:
        file_logger.info(f"From : /plan_info route. File open : config.json. Action(s) : Load JSON")
        data = json.load(f)

    file_location = os.path.join(data["disks"][location["location"]["main"]["disk"]]["location"] + user_id + "/" + file)
    
    if os.path.exists(file_location):
        file_logger.info(f"From : /delete route. File delete : {file_location}. Action(s) : File deletion initiated")
        os.remove(file_location)
    else:
        return Response(f"404 : File not found", status_code=404)

    app_logger.info(f"File {file_location} delete succesfuly")
    return Response(f"200 : The file is delete", status_code=200)

@app.post("/get_content")
async def get_content(request: Request, infos: dict = Body(...)):
    app_logger.info(f"For IP : {request.client.host} : Root endpoint accessed. Until : Get Content")
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

    email = infos["email"]
    token = infos["token"]

    if not re.match(email_regex, email):
        return Response("403 Forbidden: Adresse mail invalide !", status_code=403)

    doc_id = None
    collection_name = 'users'
    users_ref = db.collection(collection_name).where('email', '>=', email).where('email', '<=', email + '\uf8ff')

    for doc in users_ref.stream():    
        doc_id = doc.id
        stored_token = doc.to_dict().get('token')
        location = doc.to_dict().get('storage')
        user_id = doc.to_dict().get('id')
        break

    if not doc_id or stored_token != token:
        return Response("401 Token invalide", status_code=401)
    
    files_data = []

    with open("config.json", "r") as f:
        file_logger.info(f"From : /plan_info route. File open : config.json. Action(s) : Load JSON")
        data = json.load(f)

    disk_key = location["location"]["main"].get("disk", "")

    if not disk_key:
        return JSONResponse(
            content={"error": "Aucun fichier téléchargé. Veuillez télécharger un fichier pour continuer."},
            status_code=200
        )

    disk_location = data["disks"].get(disk_key, {}).get("location", "")
    if not disk_location:
        return JSONResponse(
            content={"error": f"Erreur: le disque '{disk_key}' n'existe pas dans la configuration."},
            status_code=200
        )

    folder_path = os.path.join(disk_location + user_id)
    file_logger.info(f"From : /get_content route. Folder path calculated : {folder_path}. Action(s) : Preparing to get folder")

    for file in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file)
        if os.path.isfile(file_path):
            file_name, file_extension = os.path.splitext(file)
            file_size = os.path.getsize(file_path)

            unit = "o"
            for u in ["Ko", "Mo", "Go", "To"]:
                if file_size < 1024:
                    break
                file_size /= 1024
                unit = u

            files_data.append({
                "nom": file_name,
                "extension": file_extension,
                "taille": round(file_size, 1),
                "unité": unit
            })

    app_logger.info(f"Content Load successfuly")
    return JSONResponse(content=files_data, status_code=200)

@app.post("/download_file")
async def download_file(infos: dict = Body(...)):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

    email = infos["email"]
    token = infos["token"]
    file = infos["file"]

    if not re.match(email_regex, email):
        return Response("403 Forbidden: Adresse mail invalide !", status_code=403)

    doc_id = None
    collection_name = 'users'
    users_ref = db.collection(collection_name).where('email', '>=', email).where('email', '<=', email + '\uf8ff')

    for doc in users_ref.stream():    
        doc_id = doc.id
        stored_token = doc.to_dict().get('token')
        location = doc.to_dict().get('storage')
        user_id = doc.to_dict().get('id')
        break

    if not doc_id or stored_token != token:
        return Response("401 Token invalide", status_code=401)
    
    doc_ref = db.collection('users').document(doc_id)

    doc = doc_ref.get()

    data = doc.to_dict()

    disk = data["storage"]["location"]["main"]["disk"]
    folder = data["storage"]["location"]["main"]["folder"]

    with open("config.json") as f:
        data = json.load(f)

    disk_location = data["disks"][disk]["location"]

    file_location = f"{disk_location}{folder}/{file}"

    if os.path.exists(file_location):
        return FileResponse(file_location, media_type='application/octet-stream', filename=file)
    else:
        return Response(f"404 : Fichier non trouvé ({file_location})", status_code=404)

@app.post("/get_infos")
async def download_file(infos: dict = Body(...)):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

    email = infos["email"]
    token = infos["token"]

    if not re.match(email_regex, email):
        return Response("403 Forbidden: Adresse mail invalide !", status_code=403)

    doc_id = None
    collection_name = 'users'
    users_ref = db.collection(collection_name).where('email', '>=', email).where('email', '<=', email + '\uf8ff')

    for doc in users_ref.stream():    
        doc_id = doc.id
        stored_token = doc.to_dict().get('token')
        total = doc.to_dict().get('storage').get('space')
        plan = doc.to_dict().get('plan')
        usage = doc.to_dict().get('usage')
        break

    if not doc_id or stored_token != token:
        return Response("401 Token invalide", status_code=401)
    
    doc_ref = db.collection('users').document(doc_id)

    doc = doc_ref.get()

    data = doc.to_dict()

    disk = data["storage"]["location"]["main"]["disk"]
    folder = data["storage"]["location"]["main"]["folder"]

    if not disk:
        infos_to_send = {
        "usage": usage,
        "plan": plan,
        "storage_max": total,
        "storage_used": 0,
        "storage_used_percentage": 0,

        "storage_max_GB": round(total / 1024 / 1024 / 1024, 1),
        "storage_used_GB": 0
        }

        return JSONResponse(content=infos_to_send, status_code=200)

    print(f"Valeur de disk: '{disk}'")  # Cela te permettra de voir si disk est vide ou incorrect


    with open("config.json") as f:
        disks = json.load(f)

    disk_location = disks["disks"][disk]["location"]

    folder_location = f"{disk_location}{folder}"
    
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(folder_location):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            if os.path.isfile(filepath):
                total_size += os.path.getsize(filepath)
    
    total = total * 1024 * 1024 * 1024

    percentage = total_size * 100 / total

    infos_to_send = {
        "usage": usage,
        "plan": plan,
        "storage_max": total,
        "storage_used": total_size,
        "storage_used_percentage": percentage,

        "storage_max_GB": round(total / 1024 / 1024 / 1024, 1),
        "storage_used_GB": round(total_size / 1024 / 1024 / 1024, 1)
    }

    return JSONResponse(content=infos_to_send, status_code=200)

@app.post("/get_settings")
async def get_settings(infos: dict = Body(...)):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

    email = infos["email"]
    token = infos["token"]

    if not re.match(email_regex, email):
        return Response("403 Forbidden: Adresse mail invalide !", status_code=403)

    doc_id = None
    collection_name = 'users'
    users_ref = db.collection(collection_name).where('email', '>=', email).where('email', '<=', email + '\uf8ff')

    for doc in users_ref.stream():    
        doc_id = doc.id
        stored_token = doc.to_dict().get('token')
        
        stored_family_name = doc.to_dict().get('infos').get('family_name')
        stored_name = doc.to_dict().get('infos').get('name')
        stored_email = doc.to_dict().get('email')
        stored_id = doc.to_dict().get('id')
        break

    if not doc_id or stored_token != token:
        return Response("401 Token invalide", status_code=401)
    
    infos_to_send = {
        "family_name": stored_family_name,
        "name": stored_name,
        "email": stored_email,
        "id": stored_id
    }

    return JSONResponse(content=infos_to_send, status_code=200)

@app.post("/modify_setting")
async def get_settings(infos: dict = Body(...)):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

    email = infos["email"]
    token = infos["token"]

    setting = infos["setting"]
    value = infos["new_value"]

    if not re.match(email_regex, email):
        return Response("403 Forbidden: Adresse mail invalide !", status_code=403)

    doc_id = None
    collection_name = 'users'
    users_ref = db.collection(collection_name).where('email', '>=', email).where('email', '<=', email + '\uf8ff')

    for doc in users_ref.stream():    
        doc_id = doc.id
        stored_token = doc.to_dict().get('token')
        break

    if not doc_id or stored_token != token:
        return Response("401 Token invalide", status_code=401)
    
    
    db.collection(collection_name).document(doc_id).update({setting: value})
    
    for doc in users_ref.stream():    
        stored_family_name = doc.to_dict().get('infos').get('family_name')
        stored_name = doc.to_dict().get('infos').get('name')
        stored_email = doc.to_dict().get('email')
        stored_id = doc.to_dict().get('id')
        break
    

    infos_to_send = {
        "family_name": stored_family_name,
        "name": stored_name,
        "email": stored_email,
        "id": stored_id
    }
    

    return JSONResponse(content=infos_to_send, status_code=200)

def check_space_avaible(email, token, space_needed):
    doc_id = None
    collection_name = 'users'
    users_ref = db.collection(collection_name).where('email', '>=', email).where('email', '<=', email + '\uf8ff')

    for doc in users_ref.stream():    
        doc_id = doc.id
        stored_token = doc.to_dict().get('token')
        location = doc.to_dict().get('storage')
        user_id = doc.to_dict().get('id')
        break

    if not doc_id or stored_token != token:
        return Response("401 Token invalide", status_code=401)
    
    with open("config.json", "r") as f:
        data = json.load(f)

    for disk, info in data["disks"].items():
        location = info["location"]
        free_space = data["disks"][disk]["free"]
        if free_space is not None:
            if free_space > space_needed:
                print(f"Le disque {disk} est éligible car : Espace libre sur {disk} ({location}): {free_space:.2f} GB")
                return True
            else:
                print(f"Le disque {disk} n'est pas éligible")
                return False
                
        else:
            print(f"Le disque {disk} ({location}) n'a pas pu être trouvé.")
    
@app.post("/pay_plan")
async def pay_plan(infos: dict = Body(...)):
    if infos["type"] == "with_card":
        return Response("403 : Paiement non disponible", status_code=200)
    else:
        email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

        email = infos["email"]
        token = infos["token"]

        user_code = infos["code"]
        plan = infos["plan"]

        if not re.match(email_regex, email):
            return Response("403 Forbidden: Adresse mail invalide !", status_code=403)

        doc_id = None
        collection_name = 'users'
        users_ref = db.collection(collection_name).where('email', '>=', email).where('email', '<=', email + '\uf8ff')

        for doc in users_ref.stream():    
            doc_id = doc.id
            stored_token = doc.to_dict().get('token')
            actual_plan = doc.to_dict().get('plan')
            disk = doc.to_dict().get('storage').get('location').get('main').get('disk')
            break

        if not doc_id or stored_token != token:
            return Response("401 Token invalide", status_code=401)
        
        with open("code.json", "r") as f:
            codes = json.load(f)

        for code in codes["codes"]:
            if code["email"] == email:
                print(f"Code trouvé pour l'email {email}: {code['code']}")

                if code["plan"] == plan:
                    if code["code"] == user_code:
                        if code["used"] == 1:
                            return Response(f"403 : Code déjà utilisé", status_code=403)
                        else:
                            if plan == "free":
                                return Response(f"403 : Plan invalide", status_code=403)
                            
                            check_space = check_space_avaible(email, token, STORAGE_PLANS[plan])

                            if not check_space:
                                return Response(f"403 : Espace insuffisant", status_code=403)

                            db.collection(collection_name).document(doc_id).update({"plan": plan})

                            db.collection(collection_name).document(doc_id).update({"storage.space": STORAGE_PLANS[plan]})

                            code["used"] = 1

                            
                            with open("code.json", "w") as f:
                                json.dump(codes, f, indent=4)

                            with open("config.json", "r") as f:
                                data = json.load(f)

                            # Calculer l'espace nécessaire en fonction de la différence entre les plans
                            space_more_need = STORAGE_PLANS[plan] - STORAGE_PLANS[actual_plan]

                            # Si l'espace supplémentaire est positif, cela signifie que nous avons besoin de plus d'espace
                            if space_more_need > 0:
                                data["disks"][disk]["free"] -= space_more_need
                                data["disks"][disk]["used"] += space_more_need
                            # Si l'espace est réduit, on augmente l'espace libre et réduit l'espace utilisé
                            elif space_more_need < 0:
                                data["disks"][disk]["free"] += abs(space_more_need)
                                data["disks"][disk]["used"] -= abs(space_more_need)

                            # Mettre à jour le fichier config.json avec les nouvelles valeurs
                            with open("config.json", "w") as f:
                                json.dump(data, f, indent=4)


                            return Response(f"200 : Plan changé pour {plan}", status_code=200)
                    else:
                        return Response(f"403 : Code invalide", status_code=403)
                else:
                    return Response(f"403 : Plan invalide", status_code=403)

@app.post("/share/{option}")
async def share_file(option: str, infos: dict = Body(...)):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

    email = infos["email"]
    token = infos["token"]
    file_name = infos["file"]

    if not re.match(email_regex, email):
        return Response("403 Forbidden: Adresse mail invalide !", status_code=403)

    doc_id = None
    collection_name = 'users'
    users_ref = db.collection(collection_name).where('email', '>=', email).where('email', '<=', email + '\uf8ff')

    for doc in users_ref.stream():    
        doc_id = doc.id
        stored_token = doc.to_dict().get('token')
        account_id = doc.to_dict().get('id')
        location = doc.to_dict().get('storage').get('location').get('main').get('disk')
        break

    if not doc_id or stored_token != token:
        return Response("401 Token invalide", status_code=401)
    
    with open("share.json", "r", encoding="utf-8") as file:
        data = json.load(file)

    with open("config.json", "r", encoding="utf-8") as file:
        config = json.load(file)

        # Parcours des clés de 'disks' (ex: 'disk1', 'disk2')
        for disk_key in config["disks"]:
            disk = config["disks"][disk_key]  # Accès aux informations du disque
            if disk["name"] == location:  # Vérifie si le nom du disque correspond à 'location'
                location = disk["location"]  # Assure-toi de faire une affectation correcte


    if option == "link":
        id = str(uuid.uuid4())
        data.append({
            "file_name": file_name,
            "used": "false",
            "id": id,
            "account_id": account_id,
            "location": location
        })

        with open("share.json", "w", encoding="utf-8") as file:
            json.dump(data, file, ensure_ascii=False, indent=4)

        return Response(f"http://[{host_ip}]:{host_port}/download/{id}", status_code=200)
    else:
        id = str(uuid.uuid4())
        data.append({
            "file_name": file_name,
            "used": "false",
            "id": id,
            "account_id": account_id,
            "location": location
        })

        with open("share.json", "w", encoding="utf-8") as file:
            json.dump(data, file, ensure_ascii=False, indent=4)

        url = f"http://[{host_ip}]:{host_port}/download/{id}"

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )

        qr.add_data(url)
        qr.make(fit=True)

        img = qr.make_image(fill="black", back_color="white")

        # Sauvegarder ou envoyer l'image (envoie sous forme de réponse HTTP)
        img_byte_array = BytesIO()
        img.save(img_byte_array)
        img_byte_array.seek(0)  # Retourner au début du flux de données

        return StreamingResponse(img_byte_array, media_type="image/png")

 
@app.get("/download/{file_id}")
async def download_shared(file_id: str):
    with open("share.json", "r", encoding='utf-8') as file:
        data = json.load(file)

    for link in data:
        if link["id"] == file_id:
            if link["used"] == "false":
                path = os.path.join(f"{link["location"]}/{link["account_id"]}/{link["file_name"]}")
                if not os.path.exists(path):
                    return {"message": "Fichier non trouvé"}

                return FileResponse(path, media_type='application/octet-stream', filename=link["file_name"])
    
    return Response("Link not Found", 404)


# Admin routes :

@app.post("/admin/login")
async def admin_login(infos: dict = Body(...)):
    email = infos["email"]
    password = infos["password"]

    with open("admin.json", "r") as f:
        data = json.load(f)
    
    for admin in data:
        if admin["email"] == email and admin["password"] == password:
            token = str(uuid.uuid4())
            admin["token"] = token

            with open("admin.json", "w") as f:
                json.dump(data, f, indent=4)

            return Response(f"{token}", status_code=200)
        
    return Response("401 Unauthorized", status_code=401)

@app.post("/admin/get_users")
async def get_users(infos: dict = Body(...)):
    with open("admin.json", "r") as f:
        data = json.load(f)

    for admins in data:
        if infos["token"] == admins["token"]:
            break
    else:
        return Response("401 Unauthorized", status_code=401)
        

    users_ref = db.collection('users')
    docs = users_ref.stream()

    users = []

    for doc in docs:
        user_data = doc.to_dict()
        email = user_data.get('email')
        user_id = user_data.get('id')

        if email and user_id:
            users.append({
                "email": email,
                "id": user_id
            }) 

    return JSONResponse(content=users, status_code=200)

@app.post("/admin/check")
async def check(infos: dict = Body(...)):
    with open("admin.json", "r") as f:
        data = json.load(f)

    for admins in data:
        if infos["token"] == admins["token"]:
            break
    else:
        return Response("401 Unauthorized", status_code=401)

    return Response("200", status_code=200)

@app.post("/admin/get_user_infos")
async def get_user_infos(infos: dict = Body(...)):
    with open("admin.json", "r") as f:
        data = json.load(f)

    for admin in data:
        if infos["token"] == admin["token"]:
            break
    else:
        return Response("401 Unauthorized", status_code=401)

    userId = infos["user"]

    users_ref = db.collection('users').where('id', '==', userId).stream()

    users_list = []
    for user in users_ref:
        user_data = user.to_dict()
        users_list.append(user_data)

    if not users_list:
        return Response("404 Not Found: Utilisateur introuvable", status_code=404)

    return users_list

@app.post("/admin/delete_user")
async def delete_user(infos: dict = Body(...)):
    with open("admin.json", "r") as f:
        data = json.load(f)

    for admin in data:
        if infos["token"] == admin["token"]:
            break
    else:
        return Response("401 Unauthorized", status_code=401)

    user_id = infos["user"]

    users_ref = db.collection("users")
    docs = users_ref.stream()

    for doc in docs:
        data = doc.to_dict()
        
        if data.get("id") == user_id:
            print(f"Utilisateur trouvé : {data}")
            users_ref.document(doc.id).delete()
            print(f"Utilisateur avec l'ID {user_id} supprimé avec succès.")
            return

    return Response("200", status_code=200)

@app.post("/admin/get_all_users_info")
async def get_all_users_info(infos: dict = Body(...)):
    with open("admin.json", "r") as f:
        data = json.load(f)

    # Vérification admin
    for admin in data:
        if infos["token"] == admin["token"]:
            break
    else:
        return Response("401 Unauthorized", status_code=401)

    collection_ref = db.collection("users")
    docs = collection_ref.stream()
    numberAccountUser = sum(1 for _ in docs)

    users_ref = db.collection("users")

    query = users_ref.where("token", "!=", None)
    results = query.stream()

    filtered_users = [doc for doc in results if doc.to_dict().get("token") != ""]

    activeToken = len(filtered_users)

    data_to_send = {
        "numberAlltUser": numberAccountUser,
        "activeToken": activeToken
    }

    return JSONResponse(content=data_to_send, status_code=200)

@app.post("/admin/get_disks")
async def get_all_users_info(infos: dict = Body(...)):
    with open("admin.json", "r") as f:
        data = json.load(f)

    for admin in data:
        if infos["token"] == admin["token"]:
            break
    else:
        return Response("401 Unauthorized", status_code=401)
    
    disks_list = []

    with open("config.json", "r") as f:
        file_logger.info(f"From : /admin/get_disks route. File open : config.json. Action(s) : Load JSON")
        data = json.load(f)

    for disk_name, disk_info in data["disks"].items():
        disks_list.append({
            "name": disk_name,
            "location": disk_info["location"],
            "used": disk_info["used"],
            "free": disk_info["free"]
        })

    
    return JSONResponse(content=disks_list, status_code=200)

@app.post("/admin/get_disk_info")
async def get_all_users_info(infos: dict = Body(...)):
    with open("admin.json", "r") as f:
        data = json.load(f)

    for admin in data:
        if infos["token"] == admin["token"]:
            break
    else:
        return Response("401 Unauthorized", status_code=401)
    
    disk = infos["disk"]

    with open("config.json", "r") as f:
        file_logger.info(f"From : /admin/get_disks route. File open : config.json. Action(s) : Load JSON")
        data = json.load(f)

    disk_path = data["disks"][disk]["location"]

    total, used, free = shutil.disk_usage(disk_path)

    all_folders = [f.name for f in os.scandir(disk_path) if f.is_dir()]

    system_folders = [f for f in all_folders if f in SYSTEM_FOLDERS]
    user_folders = [f for f in all_folders if f not in SYSTEM_FOLDERS]

    test_file_path = os.path.join(disk_path, "test_write_file.tmp")
    file_size_mb = 100

    start_time = time.time()
    block_size = 1024 * 1024  # 1 Mo
    blocks_written = 0
    with open(test_file_path, 'wb') as f:
        while blocks_written * block_size < file_size_mb * 1024 * 1024:
            f.write(os.urandom(block_size))
            blocks_written += 1
    elapsed_time = time.time() - start_time

    write_speed = file_size_mb / elapsed_time
    iops = blocks_written / elapsed_time

    os.remove(test_file_path)

    disk_info = {
        "VSpace": {
            "used": data["disks"][disk]["used"],
            "free": data["disks"][disk]["free"],
            "total": data["disks"][disk]["used"] + data["disks"][disk]["free"]
        },
        "RSpace": {
            "used": round(used / (1024**3), 2),
            "free": round(free / (1024**3), 2),
            "total": round(total / (1024**3), 2)
        },
        "Content": {
            "System": system_folders,
            "Account": user_folders
        },
        "Performance": {
            "read_speed_MBps": 150,
            "write_speed_MBps": round(write_speed, 2),
            "IOPS": round(iops, 2)
        }

    }

    return JSONResponse(content=disk_info, status_code=200)


    
if __name__ == "__main__":
    uvicorn.run(
        "api:app",  # Remplace "api" par le nom de ton fichier si nécessaire
        host="2a01:cb11:ecc:b300:9dd7:f038:2bc6:b17e",  # Écoute sur toutes les interfaces IPv4 et IPv6
        port=8000,
    )
