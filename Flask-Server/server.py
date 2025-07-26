from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import requests 
from keycloak import KeycloakAdmin, KeycloakOpenID
from urllib.parse import quote_plus
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from datetime import datetime



from keycloak.exceptions import (
    KeycloakGetError,
    KeycloakAuthenticationError,
    KeycloakError 
)
import logging
import json
import os

import firebase_admin
from firebase_admin import credentials, firestore

cred = credentials.Certificate("ai-assistant-3ccc8-firebase-adminsdk-fbsvc-bcd5a25bdf.json")
firebase_admin.initialize_app(cred)

db = firestore.client()


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)



KEYCLOAK_SERVER_URL = os.environ.get("KEYCLOAK_SERVER_URL") 
REALM_NAME = os.environ.get("REALM_NAME")
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")


GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")

GOOGLE_REDIRECT_URI = os.environ.get("GOOGLE_REDIRECT_URI") 
GOOGLE_CALENDAR_SCOPES = ['https://www.googleapis.com/auth/calendar.readonly']


RESET_CLIENT_ID      = os.environ.get("RESET_CLIENT_ID")               
RESET_CLIENT_SECRET  = os.environ.get("RESET_CLIENT_SECRET")  
USER_FACING_CLIENT_ID = os.environ.get("USER_FACING_CLIENT_ID")             
REDIRECT_URI  = os.environ.get("REDIRECT_URI")

_UMA_WELL_KNOWN_CONFIG = None
STATE_DIR = "user_conversations"
os.makedirs(STATE_DIR, exist_ok=True)



def get_admin_token():
    token_url = f"{KEYCLOAK_SERVER_URL.rstrip('/')}/realms/{REALM_NAME}/protocol/openid-connect/token"
    print("DEBUG: get_admin_token() çağrıldı. URL:", token_url)
    data = {
        "grant_type": "client_credentials",
        "client_id": RESET_CLIENT_ID,
        "client_secret": RESET_CLIENT_SECRET
    }
    resp = requests.post(token_url, data=data)
    print("DEBUG: get_admin_token() status code:", resp.status_code)
    try:
        token = resp.json().get("access_token")
        print("DEBUG: get_admin_token() gelen token:", token[:20], "…")
    except:
        print("DEBUG: get_admin_token() response body:", resp.text)
        token = None
    resp.raise_for_status()
    return token

def find_user_id_by_email(admin_token, email):
    url = f"{KEYCLOAK_SERVER_URL.rstrip('/')}/admin/realms/{REALM_NAME}/users"
    print("DEBUG: find_user_id_by_email() çağrıldı. URL:", url)
    print("DEBUG: find_user_id_by_email() token:", admin_token and admin_token[:20], "…")
    print("DEBUG: find_user_id_by_email() params:", {"email": email})

    headers = {"Authorization": f"Bearer {admin_token}"}
    params = {"email": email}
    resp = requests.get(url, headers=headers, params=params)
    print("DEBUG: find_user_id_by_email() status code:", resp.status_code)
    try:
        users = resp.json()
        print("DEBUG: find_user_id_by_email() returned users list:", users)
    except:
        print("DEBUG: find_user_id_by_email() response body:", resp.text)
        users = []

    if not users:
        return None
    return users[0]["id"]

def send_reset_password_email(admin_token, user_id, client_id, redirect_uri):
    
    base = f"{KEYCLOAK_SERVER_URL.rstrip('/')}/admin/realms/{REALM_NAME}"
    url = f"{base}/users/{user_id}/execute-actions-email"

    headers = {
        "Authorization": f"Bearer {admin_token}",
        "Content-Type": "application/json"
    }
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri
    }

    payload = ["UPDATE_PASSWORD"]

    logger.info("🔗 execute-actions-email URL: %s", url)
    logger.info("🔗 Params: %s", params)
    logger.info("✉️ Body: %s", payload)

    try:
        resp = requests.put(url, headers=headers, params=params, json=payload)
        logger.info("✉️ status code: %d", resp.status_code)
        return resp.status_code == 204
    except requests.RequestException as e:
        logger.error("⚠️ send_reset_password_email failed", exc_info=True)
        return False

def check_user_do(access_token, token_info, requested_permissions_str):
    permission_granted_by_uma = False
    try:
        uma_config = get_uma_well_known_config()
        if not uma_config or "token_endpoint" not in uma_config:
            logger.error("UMA token_endpoint not found in well-known configuration.")
            return False

        token_endpoint = uma_config["token_endpoint"]

        payload = {
            "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
            "permission": requested_permissions_str,
            "response_mode": "decision",
            "audience": CLIENT_ID,
        }
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        logger.info(f"Attempting UMA permission check (manual request) for resource '{requested_permissions_str}' to {token_endpoint}")
        logger.debug(f"UMA Payload: {payload}")

        uma_response = requests.post(token_endpoint, data=payload, headers=headers, verify=True)

        logger.info(f"UMA permission check response status: {uma_response.status_code}")
        logger.debug(f"UMA permission check response body: {uma_response.text}")

        if uma_response.status_code == 200:
            response_data = uma_response.json()
            if response_data.get("result") is True:
                permission_granted_by_uma = True
                logger.info(f"UMA permission granted (manual request) for user {token_info.get('preferred_username', 'N/A')}.")
                return True
            else:
                logger.warning(f"UMA permission denied by server (manual request) for user {token_info.get('preferred_username', 'N/A')}. Response: {response_data}")
        elif uma_response.status_code == 403:
            logger.warning(f"UMA permission denied (403, manual request) for user {token_info.get('preferred_username', 'N/A')}. Response: {uma_response.text}")
        else:
            logger.error(f"Error during UMA permission check (manual request). Status: {uma_response.status_code}, Body: {uma_response.text}")
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error during manual UMA permission check: {e}", exc_info=True)
        
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing UMA response JSON (manual request): {e}", exc_info=True)
        
    except Exception as e:
        logger.error(f"Unexpected error during manual UMA permission check: {e}", exc_info=True)
    if not permission_granted_by_uma:
        return False

def get_uma_well_known_config():
    global _UMA_WELL_KNOWN_CONFIG
    if _UMA_WELL_KNOWN_CONFIG:
        return _UMA_WELL_KNOWN_CONFIG

    well_known_url = f"{KEYCLOAK_SERVER_URL.rstrip('/')}/realms/{REALM_NAME}/.well-known/uma2-configuration"
    try:
        response = requests.get(well_known_url, verify=True)
        response.raise_for_status()
        _UMA_WELL_KNOWN_CONFIG = response.json()
        logger.info(f"Fetched UMA well-known config: {_UMA_WELL_KNOWN_CONFIG}")
        return _UMA_WELL_KNOWN_CONFIG
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch UMA well-known configuration from {well_known_url}: {e}", exc_info=True)
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse UMA well-known configuration JSON from {well_known_url}: {e}", exc_info=True)
        return None

def get_keycloak_openid():
    return KeycloakOpenID(
        server_url=KEYCLOAK_SERVER_URL,
        client_id=CLIENT_ID,
        realm_name=REALM_NAME,
        client_secret_key=CLIENT_SECRET,
        verify=True
    )

def get_keycloak_admin_with_user_token():
    full_token_payload = session.get('tokens')
    if not full_token_payload:
        raise PermissionError("Admin access required. Full token payload not found in session.")

    return KeycloakAdmin(
        server_url=KEYCLOAK_SERVER_URL,
        realm_name=REALM_NAME,
        client_id=CLIENT_ID,
        client_secret_key=CLIENT_SECRET,
        token=full_token_payload,
        verify=True
    )

keycloack_admin_connection =KeycloakAdmin(
        server_url=KEYCLOAK_SERVER_URL,
        realm_name=REALM_NAME,
        client_id=CLIENT_ID,
        client_secret_key=CLIENT_SECRET,
        verify=True
    )

def get_user_path(username):
    return os.path.join(STATE_DIR, f"{username}.json")

def load_conversation(username):
    path = get_user_path(username)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"contents": []}

def save_conversation(username, contents):
    path = get_user_path(username)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"contents": contents}, f, indent=2, ensure_ascii=False)

def append_message(username, role, text):
    convo = load_conversation(username)
    convo["contents"].append({
        "role": role,
        "parts": [{"text": text}]
    })
    save_conversation(username, convo["contents"])

def delete_user_file():
    username = session.get("username")
    if username:
        path = os.path.join("user_conversations", f"{username}.json")
        logger.info(f"🗑️ Kullanıcı dosyası silindi: {path}")
        if os.path.exists(path):
            os.remove(path)
            logger.info(f"🗑️ Kullanıcı dosyası silindi: {path}")
        else:
            logger.info(f"ℹ️ Silinecek dosya bulunamadı: {path}")

def get_userinfo(access_token=None):
    
    if access_token is None:
        access_token = session.get("access_token")

    if not access_token:
        logger.warning("get_userinfo called without an access token.")
        return None

    keycloak_oidc = get_keycloak_openid()
    try:
        user_info = keycloak_oidc.userinfo(access_token)
    except KeycloakError as e:
        logger.error(f"Token validation failed or could not get userinfo: {e}", exc_info=True)
        return None

    preferred_username = user_info.get("preferred_username")
    email = user_info.get("email")

    if not email:
        logger.error("No email address found in the token.")
        return None

    try:
        admin_conn = keycloack_admin_connection
        user_records = admin_conn.get_users({"email": email})
        if not user_records:
            logger.warning(f"User with email '{email}' from token not found in Keycloak.")
            return {
                "username": preferred_username,
                "email": email,
                "given_name": user_info.get("given_name", ""),
                "family_name": user_info.get("family_name", ""),
                "groups": [],
                "roles": [],
                "phoneNumber": ""
            }
        
        user_id = user_records[0]['id']
        user_data = admin_conn.get_user(user_id)
        groups = admin_conn.get_user_groups(user_id)
        roles = admin_conn.get_realm_roles_of_user(user_id)

        return {
            "username": preferred_username,
            "email": user_data.get("email"),
            "given_name": user_info.get("given_name", ""),
            "family_name": user_info.get("family_name", ""),
            "phoneNumber": user_data.get("attributes", {}).get("phoneNumber", [""])[0],
            "groups": [g['name'] for g in groups],
            "roles": [r['name'] for r in roles if r["name"] not in ["uma_authorization", "offline_access", "default-roles-main"]]
        }
    except Exception as e:
        logger.error(f"Failed to get user details (groups/roles) for '{email}': {e}", exc_info=True)
        return {
            "username": preferred_username,
            "email": email,
            "given_name": user_info.get("given_name", ""),
            "family_name": user_info.get("family_name", ""),
            "groups": [],
            "roles": [],
            "phoneNumber": ""
        }

def get_announcements(limit=1):
    
    try:
        docs = (
            db.collection("announcements")
              .order_by("timestamp", direction=firestore.Query.DESCENDING)
              .limit(limit)
              .stream()
        )
        return [doc.to_dict() for doc in docs]
    except Exception as e:
        # Hata durumunda boş liste döndür
        return []

def get_google_calendar_context(username, user_info):
    has_google_auth = False
    encoded_email = None
    if username:
        try:
            google_creds_doc = db.collection('google_tokens').document(username).get()
            if google_creds_doc.exists:
                has_google_auth = True
                if user_info and user_info.get('email'):
                    encoded_email = quote_plus(user_info['email'])
        except Exception as e:
            logger.error(f"Failed to check Google credentials for {username}: {e}", exc_info=True)
            # Defaults are already False/None, so we can just log and continue
    return {"has_google_auth": has_google_auth, "encoded_email": encoded_email}

def get_session_username():
    access_token = session.get("access_token")
    if not access_token:
        logger.info("No access token found in session for get_session_username, returning None.")
        return None
    
    username = session.get("username")
    logger.info("usernameee: %s", username)
    return username
    



@app.route('/announcement', methods=['POST'])
def announcement():
    # 1. Get token from Authorization header or session
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        access_token = auth_header.split(" ", 1)[1]
    else:
        access_token = session.get("access_token")

    if not access_token:
        return jsonify({"error": "An access token is required for this operation."}), 401

    try:
        # 2. Validate token and get user info
        keycloak_oidc = get_keycloak_openid()
        token_info = keycloak_oidc.introspect(access_token)
        if not token_info.get("active", False):
            return jsonify({"error": "Token is not active."}), 401
            
        permission_to_check = "announcement"
        if not check_user_do(access_token, token_info, permission_to_check):
            logger.warning(f"User {token_info.get('preferred_username', 'N/A')} denied access for permission '{permission_to_check}'.")
            return jsonify({"error": f"Authorization failed: Required permission '{permission_to_check}' is missing."}), 403

        # 4. Get user info using the retrieved token
        user = get_userinfo(access_token=access_token)
        if not user:
            return jsonify({"error": "Invalid token or user could not be identified."}), 401
        
        # 5. Ensure the sender is the authenticated user
        sender_username = user.get("username")
        
        # 6. Get content from request body
        data = request.get_json()
        if not data or 'content' not in data:
            return jsonify({"error": "Missing 'content' in request body."}), 400

        # 7. Prepare announcement data for Firestore
        now = datetime.now()
        timestamp_str = now.strftime("%Y-%m-%d %H:%M:%S")
        announcement_data = {
            "sender": sender_username,
            "content": data["content"],
            "date": timestamp_str.split(" ")[0],
            "time": timestamp_str.split(" ")[1],
            "timestamp": now
        }

        # 8. Add to Firestore
        db.collection("announcements").add(announcement_data)

        return jsonify({"status": "success", "saved": announcement_data}), 200

    except KeycloakError as e:
        logger.error(f"Token introspection failed for /announcement route: {e}")
        return jsonify({"error": "Token validation failed."}), 401
    except Exception as e:
        logger.error(f"An unexpected error occurred in /announcement: {e}", exc_info=True)
        return jsonify({"error": "An internal server error occurred."}), 500
    
@app.route('/edit_user/<username>', methods=['GET', 'POST'])
def edit_user(username):
    # 1. Token kontrolü
    access_token = session.get("access_token")
    if not access_token:
        return redirect(url_for('login'))

    # 2. Token introspect ile doğrulama
    keycloak_oidc = get_keycloak_openid()
    try:
        token_info = keycloak_oidc.introspect(access_token)
        if not token_info.get("active", False):
            session.clear()
            return redirect(url_for('login', error="Session süreniz dolmuş."))        
    except Exception:
        session.clear()
        return redirect(url_for('login', error="Token doğrulama hatası."))

    # 3. Login olmuş kullanıcıyı al (popup için)
    current_user = get_userinfo()
    # Popup'taki "department" alanı için group listesinden ilk grubu department olarak atayabilirsiniz:
    if current_user and "groups" in current_user and current_user["groups"]:
        current_user["department"] = current_user["groups"][0]
    else:
        current_user["department"] = ""

    # 4. Düzenlenecek kullanıcıyı bulmak için Keycloak Admin kullanıcısı
    try:
        admin_conn = get_keycloak_admin_with_user_token()
    except Exception as e:
        # Eğer admin token yoksa, login sayfasına yönlendir
        return redirect(url_for('login', error="Yönetici yetkisi alınamadı. Lütfen tekrar giriş yapın."))

    users = admin_conn.get_users({"username": username})
    check_register_permisson = check_user_do(access_token, token_info, "register_endpoint")
    announcements = get_announcements(limit=1)

    if not users:
        return f"Kullanıcı bulunamadı: {username}", 404

    user_id = users[0]['id']

    if request.method == 'POST':
        data = request.form
        update_data = {
            "firstName": data.get("firstName"),
            "lastName": data.get("lastName"),
            "email": data.get("email"),
            "attributes": {
            "phoneNumber": data.get("phoneNumber", "")
            }
        }

        selected_group_name = data.get("group")
        selected_role_name = data.get("role")

        admin_conn.update_user(user_id=user_id, payload=update_data)

        
        if selected_group_name:
            # Kullanıcının tüm gruplarını alıp, varsa önce sil
            mevcut_gruplar = admin_conn.get_user_groups(user_id)
            for g in mevcut_gruplar:
                admin_conn.group_user_remove(user_id=user_id, group_id=g["id"])
            # Yeni grubu ata
            all_groups = admin_conn.get_groups()
            group_to_assign = next((g for g in all_groups if g["name"] == selected_group_name), None)
            if group_to_assign:
                admin_conn.group_user_add(user_id=user_id, group_id=group_to_assign["id"])

        # 5.c. Role güncelleme:
        if selected_role_name:
            # Kullanıcının mevcut rollerini al (realm rolü baz alınıyor)
            mevcut_roller = admin_conn.get_realm_roles_of_user(user_id)
            # Önce tüm rolleri sil
            for r in mevcut_roller:
                if r["name"] not in ["offline_access", "uma_authorization", "default-roles-main"]:
                    admin_conn.delete_realm_roles_of_user(user_id=user_id, roles=[{"id": r["id"], "name": r["name"]}])
            # Yeni rolü ata
            try:
                new_role = admin_conn.get_realm_role(selected_role_name)
                admin_conn.assign_realm_roles(user_id=user_id, roles=[{"id": new_role["id"], "name": new_role["name"]}])
            except Exception:
                pass

        return redirect(url_for('all_users'))

    # 6. GET ise: "düzenlenecek kullanıcı" bilgilerini al
    user_info = admin_conn.get_user(user_id)   # Bu, yalnızca temel kullanıcı objesini içerir

    # 7. "Department" (grup) ve "Role" dropdown'larını doldurmak için:
    try:
        all_groups = [g["name"] for g in admin_conn.get_groups()]
    except Exception:
        all_groups = []
    try:
        all_roles = [r["name"] for r in admin_conn.get_realm_roles()
                     if r["name"] not in ["uma_authorization", "offline_access", "default-roles-main"]]
    except Exception:
        all_roles = []

    calendar_context = get_google_calendar_context(current_user.get('username'), current_user)
    
    return render_template(
        "edit_user.html",
        user = user_info,
        current_user = current_user,
        groups = all_groups,
        roles = all_roles,
        can_do_Register = check_register_permisson,
        announcements = announcements,
        **calendar_context
    )

@app.route('/delete_user/<username>', methods=['POST'])
def delete_user(username):
    try:
        access_token = session.get("access_token")
        if 'access_token' not in session:
            return redirect(url_for('login'))

        admin_conn = get_keycloak_admin_with_user_token()
        users = admin_conn.get_users({ "username": username })

        if not users:
            return f"Kullanıcı bulunamadı: {username}", 404
        
        user_id = users[0]['id']
        admin_conn.delete_user(user_id)
        return redirect(url_for('all_users'))
    
    except Exception as e:
        return f"Hata oluştu: {str(e)}", 500

@app.route('/all_users', methods=['GET'])
def all_users():
    try:
        access_token = session.get("access_token")
        if not access_token:
            return redirect(url_for('login'))
        
        keycloak_oidc = get_keycloak_openid()
        token_info = keycloak_oidc.introspect(access_token)
        if not token_info.get("active", False):
            session.clear()
            return redirect(url_for('login', error="Session süresi doldu. Lütfen tekrar giriş yapın."))

        current_user = get_userinfo()
        if current_user and "groups" in current_user and current_user["groups"]:
            current_user["department"] = current_user["groups"][0]
        else:
            current_user["department"] = ""

        # 3. Admin bağlantısıyla tüm kullanıcı listesini alın:
        admin_conn = keycloack_admin_connection
        users = admin_conn.get_users({})

        # 4. "Kayıt edebilme" iznini kontrol edin:
        check_register_permisson = check_user_do(access_token, token_info, "register_endpoint")
        announcements = get_announcements(limit=1)

        user_list = []
        for u in users:
            user_id = u.get("id")
            user_details = admin_conn.get_user(user_id)
            groups = admin_conn.get_user_groups(user_id)
            roles = admin_conn.get_realm_roles_of_user(user_id)
            username = user_details.get("username")

            if username == "admin":
                continue

            user_info = {
                "username": user_details.get("username"),
                "email": user_details.get("email"),
                "firstName": user_details.get("firstName", ""),
                "lastName": user_details.get("lastName", ""),
                "phoneNumber": user_details.get("attributes", {}).get("phoneNumber", [""])[0],
                "groups": [g['name'] for g in groups],
                "roles": [r['name'] for r in roles if r['name'] not in ["offline_access", "uma_authorization", "default-roles-main"]]
            }
            user_list.append(user_info)

        # 6. Google Calendar bilgilerini al
        calendar_context = get_google_calendar_context(current_user.get('username'), current_user)

        # 7. Şablona render ederken hem `users` listesi hem de `current_user` (department dâhil) yollanıyor:
        return render_template(
            "all_users.html",
            users=user_list,
            user=current_user,
            can_do_Register=check_register_permisson,
            announcements=announcements,
            **calendar_context
        )

    except Exception as e:
        return f"Hata: {str(e)}", 500

@app.route('/announcements', methods=['GET'])
def announcements():
    try:
        # 1. Oturum kontrolü
        access_token = session.get("access_token")
        if not access_token:
            return redirect(url_for("login", error="Oturum bulunamadı."))

        # 2. KeycloakOpenID ile token doğrulama
        keycloak_oidc = get_keycloak_openid()
        try:
            token_info = keycloak_oidc.introspect(access_token)
        except KeycloakError:
            session.clear()
            return redirect(url_for("login", error="Token doğrulanamadı."))
        if not token_info.get("active", False):
            session.clear()
            return redirect(url_for("login", error="Oturum süreniz dolmuş."))
        
        check_register_permisson = check_user_do(access_token, token_info, "register_endpoint")
        current_user = get_userinfo(access_token=access_token)
        if not current_user:
            session.clear()
            return redirect(url_for("login", error="Kullanıcı bilgileri alınamadı."))

        current_user["department"] = current_user["groups"][0] if current_user["groups"] else ""

        # 4. Google Calendar context'ini al
        calendar_context = get_google_calendar_context(current_user.get('username'), current_user)

        # 5. Firestore'dan son 3 duyuruyu çek
        docs = (
            db.collection("announcements")
              .order_by("timestamp", direction=firestore.Query.DESCENDING)
              .limit(3)
              .stream()
        )
        announcement_list = [doc.to_dict() for doc in docs]

        # 6. Şablonu render ederken artık "user" yerine "current_user" ismiyle gönderelim:
        return render_template(
            "announcements.html",
            announcements=announcement_list,
            can_do_Register=check_register_permisson,
            current_user=current_user,
            **calendar_context
        )

    except KeycloakError as e:
        logger.error(f"Token introspection failed for /announcements route: {e}")
        return jsonify({"error": "Token validation failed."}), 401
    except Exception as e:
        return f"Veri çekme hatası: {e}", 500

@app.route('/profile')
def profile():
    access_token = session.get('access_token')

    if not access_token:
        return redirect(url_for('login', error="Session expired or not logged in."))
    
    user = get_userinfo()
    keycloak_oidc = get_keycloak_openid()

    token_info = keycloak_oidc.introspect(access_token)

    announcements = get_announcements(limit=1)

    check_register_permisson = check_user_do(access_token, token_info, "register_endpoint")

    if not user:
        return redirect(url_for('login', error="Oturum süresi dolmuş olabilir."))
    
    calendar_context = get_google_calendar_context(user.get('username'), user)
    return render_template('profile.html', user=user, can_do_Register=check_register_permisson, announcements=announcements, **calendar_context)

@app.route('/prompt', methods=['POST'])
def prompt():
    # 1. Get token from Authorization header or session
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        access_token = auth_header.split(" ", 1)[1]
    else:
        access_token = session.get("access_token")

    username = session.get("username")

    if not all([access_token, username]):
        return jsonify({"error": "User session not found or expired."}), 401

    # 2. Get prompt from request body
    data = request.get_json()
    prompt_text = data.get("prompt")
    if not prompt_text:
        return jsonify({"error": "prompt text is missing"}), 400

    # 3. Append user message to conversation history
    append_message(username, "user", prompt_text)

    # 4. Call n8n workflow
    try:
        conversation = load_conversation(username)
        # The access token is no longer sent in the body, it's sent in the header.
        n8n_payload = {
            "contents": conversation["contents"],
        }
        
        n8n_headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}"
        }

        n8n_response = requests.post(
            "http://n8n:5678/webhook/prompt",
            json=n8n_payload,
            headers=n8n_headers,
            timeout=60 # Add a timeout
        )
        logger.info(f"n8n_response: {n8n_response}")

        # 5. Handle response from n8n
        if n8n_response.status_code != 200:
            logger.error(f"n8n workflow returned an error. Status: {n8n_response.status_code}, Body: {n8n_response.text}")
            return jsonify({"error": "The workflow service returned an error."}), 502

        try:
            n8n_data = n8n_response.json()
        except ValueError:
            logger.error(f"Failed to decode JSON from n8n. Response body: {n8n_response.text}")
            delete_user_file()
            return jsonify({"error": "Received an invalid response from the workflow service."}), 502
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Could not connect to n8n workflow: {e}", exc_info=True)
        return jsonify({"error": f"Could not connect to the workflow service."}), 500

    # 6. Save the model's response
    # SECURITY: Make a copy of the data for saving, and remove any sensitive
    # information that shouldn't be stored in the conversation log.
    data_to_save = n8n_data.copy()
    if 'access_token' in data_to_save:
        del data_to_save['access_token']

    model_message_to_save = json.dumps(data_to_save, ensure_ascii=False)
    append_message(username, "model", model_message_to_save)

    # 7. Return response to client
    # As requested, the access_token is returned to the client.
    # Be aware of the security implications of this.
    return jsonify({
        "text": n8n_data.get("message") or n8n_data.get("text", "🤖 Yanıt yok"),
        "action": n8n_data.get("action", "general_chat"),
        "access_token": access_token 
    }), 200

@app.route('/')
def home():
    access_token = session.get('access_token')
    if not access_token:
        return redirect(url_for('login', error="Session expired or not logged in."))
    try:
        keycloak_oidc = get_keycloak_openid()
        token_info = keycloak_oidc.introspect(access_token)
        if not token_info.get('active', False):
            logger.warning("Access token is no longer active. Clearing session.")
            session.clear()
            return redirect(url_for('login', error="Session expired. Please log in again."))

        user_info = get_userinfo()
        if not user_info:
            logger.warning("Could not retrieve user info. Clearing session.")
            session.clear()
            return redirect(url_for('login', error="Could not retrieve user details."))
            
        message = request.args.get('message')
        announcements = get_announcements(limit=1)
        check_register_permisson = check_user_do(access_token, token_info, "register_endpoint")

        # Check for Google Calendar authorization
        username = user_info.get('username')
        calendar_context = get_google_calendar_context(username, user_info)
        
        return render_template('index.html', user=user_info, message=message, can_do_Register=check_register_permisson,announcements=announcements, **calendar_context)
    except KeycloakError as e: # Catch general Keycloak errors
        response_code = getattr(e, 'response_code', 'N/A')
        response_body = getattr(e, 'response_body', str(e))
        logger.error(f"Keycloak error on home page: {response_code} - {response_body}", exc_info=True)
        session.clear()
        return redirect(url_for('login', error="An error occurred with your session. Please log in again."))
    except Exception as e:
        logger.error(f"Error on home page: {e}", exc_info=True)
        session.clear()
        return redirect(url_for('login', error="An unexpected error occurred. Please log in again."))
    
@app.route('/mail', methods=['POST', 'GET'])
def take_data():
    # 1. Get token from Authorization header or session
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        access_token = auth_header.split(" ", 1)[1]
    else:
        access_token = session.get("access_token")

    if not access_token:
        return jsonify({"error": "An access token is required."}), 401

    # 2. Validate token and check permissions
    keycloak_oidc = get_keycloak_openid()
    try:
        token_info = keycloak_oidc.introspect(access_token)
        if not token_info.get("active", False):
            return jsonify({"error": "Token is not active."}), 401
    except KeycloakError as e:
        logger.error(f"Token introspection failed for /mail route: {e}")
        return jsonify({"error": "Token validation failed."}), 401

    permission_to_check = "mail"
    if not check_user_do(access_token, token_info, permission_to_check):
        logger.warning(f"User {token_info.get('preferred_username', 'N/A')} denied access for permission '{permission_to_check}'.")
        return jsonify({"error": f"Authorization failed: Required permission '{permission_to_check}' is missing."}), 403

    # 3. Process the request data
    data = request.get_json()
    print("Gelen data:", data)

    if not data:
        return jsonify({"error": "Eksik veri"}), 400

    # Gerekli alanları al
    department = data.get("department")


    # Eksik alan kontrolü
    if not department:
        return jsonify({"error": "department eksik"}), 400

    # ✅ Keycloak bağlantısı
    keycloak_admin_con = keycloack_admin_connection

    try:
        groups = keycloak_admin_con.get_groups()
    except Exception as e:
        return jsonify({"error": f"Gruplar alınamadı: {str(e)}"}), 500

    # Departmanı eşleştir
    matched_group_id = next(
        (group['id'] for group in groups if group["name"].lower() == department.lower()), 
        None
    )

    if not matched_group_id:
        return jsonify({"error": f"{department} grubu bulunamadı"}), 404

    try:
        users = keycloak_admin_con.get_group_members(matched_group_id)
    except Exception as e:
        return jsonify({"error": f"Kullanıcılar alınamadı: {str(e)}"}), 500

    emails = [u.get("email") for u in users if u.get("email")]
    print("Alınan e-posta adresleri:", emails)

    try:
        prompt_data = {
            "message": data.get("message", ""),
            "emails": emails
        }

        prompt_response = requests.post(
            "http://localhost:5678/webhook/prompt",
            json=prompt_data,
            headers={"Content-Type": "application/json"}
        )

        if prompt_response.status_code != 200:
            print("n8n'e gönderim başarısız:", prompt_response.text)

    except Exception as e:
        print("n8n'e gönderim hatası:", str(e))

    return jsonify({
        "status": "ok",
        "emails": emails
    }), 200

@app.route('/meeting', methods=['POST'])
def create_meeting():
    access_token = session.get("access_token")
    if not access_token:
        # Check for Bearer token in Authorization header for service-to-service calls
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            access_token = auth_header.split(' ')[1]
            
    logger.info(f"access_token2: {access_token}")
    if not access_token:
        return jsonify({"error": "Acces token is null."}), 401

    # 1. Token'ın hâlâ aktif olup olmadığını kontrol edebilirsiniz:
    keycloak_oidc = get_keycloak_openid()
    token_info = keycloak_oidc.introspect(access_token)
    if not token_info.get("active", False):
        session.clear()
        return redirect(url_for('login', error="Session süresi doldu. Lütfen tekrar giriş yapın."))

    permission_to_check = "meeting"
    if not check_user_do(access_token, token_info, permission_to_check):
        logger.warning(f"User {token_info.get('preferred_username', 'N/A')} denied access for permission '{permission_to_check}'.")
        return jsonify({"error": f"Authorization failed: Required permission '{permission_to_check}' is missing."}), 403
    
    # ——— 3. İŞİN ASIL KISMINA GEÇ: JSON'I PARSE ET ———
    data = request.get_json()
    if not data:
        return jsonify({"error": "Eksik JSON verisi"}), 400

    department = data.get("department")
    date = data.get("date")
    time = data.get("time")
    description = data.get("description", "")
    body = data.get("body", "")


    # Eksik alan kontrolü
    if not department:
        return jsonify({"error": "department eksik"}), 400
    if not date:
        return jsonify({"error": "date eksik"}), 400
    if not time:
        return jsonify({"error": "time eksik"}), 400

    # ——— 4. KEYCLOAK ADMIN CONNECT İLE GRUPLARI AL ———
    keycloak_admin_con = keycloack_admin_connection
    try:
        groups = keycloak_admin_con.get_groups()
    except Exception as e:
        return jsonify({"error": f"Keycloak gruplar alınamadı: {str(e)}"}), 500

    # department adını küçük harfe çevirerek eşleştirme
    matched_group_id = next(
        (group["id"] for group in groups if group["name"].lower() == department.lower()),
        None
    )
    if not matched_group_id:
        return jsonify({"error": f"{department} grubu bulunamadı"}), 404

    try:
        users = keycloak_admin_con.get_group_members(matched_group_id)
    except Exception as e:
        return jsonify({"error": f"Kullanıcılar alınamadı: {str(e)}"}), 500

    emails = [u.get("email") for u in users if u.get("email")]
    print("Toplantı katılımcıları:", emails)

    # ——— 5. CEVABI D Ö N ———
    return jsonify({
        "status": "success",
        "emails": emails,
        "department": department,
        "description": description,
        "date": date,
        "time": time,
        "body": body
    }), 200

@app.route('/file', methods=['POST'])
def handle_file():
    # 1. Get token from Authorization header or session
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        access_token = auth_header.split(" ", 1)[1]
    else:
        access_token = session.get("access_token")

    if not access_token:
        return jsonify({"error": "An access token is required."}), 401

    # 2. Validate token and get user info to check permissions
    keycloak_oidc = get_keycloak_openid()
    try:
        token_info = keycloak_oidc.introspect(access_token)
        if not token_info.get("active", False):
            return jsonify({"error": "Token is not active."}), 401
    except KeycloakError as e:
        logger.error(f"Token introspection failed: {e}")
        return jsonify({"error": "Token validation failed."}), 401

    # 3. Check for 'file' permission
    permission_to_check = "file"
    if not check_user_do(access_token, token_info, permission_to_check):
        logger.warning(f"User {token_info.get('preferred_username', 'N/A')} denied access for permission '{permission_to_check}'.")
        return jsonify({"error": f"Authorization failed: Required permission '{permission_to_check}' is missing."}), 403

    # 4. Process the request data
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON data"}), 400

    file_name = data.get("fileName")
    content = data.get("content")

    if not all([file_name, content]):
        return jsonify({"error": "Missing 'fileName' or 'content' in request body."}), 400

    # In a real application, you would save this to a file system or database
    logger.info(f"Received file '{file_name}' from user {token_info.get('preferred_username', 'N/A')}.")

    return jsonify({
        "status": "success",
        "message": f"File '{file_name}' processed successfully."
    }), 200

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        error = request.args.get('error')
        message = request.args.get('message')
        return render_template('login.html', error=error, message=message)

    data = request.form
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return render_template('login.html', error="Email and password are required.")

    try:
        keycloak_oidc = get_keycloak_openid()
        
        tokens = keycloak_oidc.token(username=email, password=password)

        logger.info(tokens)

        session['tokens'] = tokens
        session['access_token'] = tokens['access_token']
        session['refresh_token'] = tokens['refresh_token']

        a = session['access_token'] 
        logger.info(f"access_token: {a}")

        decoded_token = keycloak_oidc.introspect(tokens['access_token'])
        session['username'] = decoded_token.get("preferred_username") or decoded_token.get("email")

        logger.info(f"User {email} logged in successfully as {session['username']}.")

        logger.info(f"User {email} logged in successfully.")

        return redirect(url_for('home'))
    except KeycloakAuthenticationError as e:
        error_desc = getattr(e, 'error_description', None) or getattr(e, 'response_body', str(e))
        logger.warning(f"Login failed for {email}: {error_desc}")
        return render_template('login.html', error="Invalid credentials.")
    except KeycloakError as e:
        response_code = getattr(e, 'response_code', 'N/A')
        response_body = getattr(e, 'response_body', str(e))
        logger.error(f"Keycloak error during login for {email}: {response_code} - {response_body}", exc_info=True)
        return render_template('login.html', error="Login service unavailable. Please try again later.")
    except Exception as e:
        logger.error(f"Unexpected error during login for {email}: {e}", exc_info=True)
        return render_template('login.html', error="An unexpected error occurred during login.")

@app.route('/register', methods=['GET', 'POST'])
def register():
    access_token = session.get("access_token")
    if not access_token:
        return redirect(url_for('login', error="You must be logged in to register new users."))

    keycloak_oidc = get_keycloak_openid()
    try:
        token_info = keycloak_oidc.introspect(access_token)
        if not token_info.get('active', False):
            session.clear()
            return redirect(url_for('login', error="Session expired. Please log in again."))
    except KeycloakError as e:
        response_code = getattr(e, 'response_code', 'N/A')
        response_body = getattr(e, 'response_body', str(e))
        logger.error(f"Token introspection failed: {response_code} - {response_body}", exc_info=True)
        session.clear()
        return redirect(url_for('login', error="Session validation failed. Please log in again."))
    except Exception as e:
        logger.error(f"Unexpected error during token introspection: {e}", exc_info=True)
        session.clear()
        return redirect(url_for('login', error="An unexpected error occurred validating your session."))
    
    check_register_permission = check_user_do(access_token, token_info, "register_endpoint")
    
    if check_register_permission is False:
        return redirect(url_for('home',message="You are not have a permisson to register user."))

    try:
        admin_conn = get_keycloak_admin_with_user_token()
    except PermissionError as e:
        logger.warning(f"Admin token missing for registration actions: {e}")
        return redirect(url_for('login', error=str(e)))
    except KeycloakError as e:
        response_code = getattr(e, 'response_code', 'N/A')
        response_body = getattr(e, 'response_body', str(e))
        logger.error(f"Keycloak admin connection failed: {response_code} - {response_body}", exc_info=True)
        return jsonify({"error": "Failed to establish admin connection to Keycloak. Your token might lack necessary privileges."}), 500
    except Exception as e:
        logger.error(f"Unexpected error getting admin_conn: {e}", exc_info=True)
        return jsonify({"error": "Unexpected error preparing for registration."}), 500

    if request.method == 'GET':
        try:
            groups = [group["name"] for group in admin_conn.get_groups()]
            roles = [role["name"] for role in admin_conn.get_realm_roles() if role["name"] not in ["uma_authorization", "offline_access", "default-roles-main"]]
            return render_template('register.html', groups=groups, roles=roles)
        except KeycloakError as e:
            response_code = getattr(e, 'response_code', 'N/A')
            response_body = getattr(e, 'response_body', str(e))
            logger.error(f"Failed to fetch groups/roles (KeycloakError): {response_code} - {response_body}", exc_info=True)
            return jsonify({"error": "Failed to fetch registration prerequisites from Keycloak."}), 500
        except Exception as e:
            logger.error(f"Failed to fetch groups/roles for registration form: {e}", exc_info=True)
            return jsonify({"error": "Failed to fetch registration prerequisites."}), 500
    else:  # POST
        data = request.form
        selected_group_name = data.get("group")
        selected_role_name = data.get("role")
        email = data.get("email")
        firstname = data.get("firstname")
        lastname = data.get("lastname")
        phoneNumber = data.get("phoneNumber", "")

        if not all([email, firstname, lastname, selected_group_name, selected_role_name]):
             return jsonify({"error": "All fields (Email, Firstname, Lastname, Group, Role) are required for registration."}), 400
        try:
            all_groups = admin_conn.get_groups()
            group_id_to_assign = next((g['id'] for g in all_groups if g['name'] == selected_group_name), None)
            if not group_id_to_assign:
                logger.warning(f"Attempt to register user with non-existent group: '{selected_group_name}'")
                return jsonify({"error": f"Group '{selected_group_name}' not found."}), 400

            role_to_assign_obj = admin_conn.get_realm_role(selected_role_name) # Raises KeycloakGetError if not found

            user_data = {
                "username": email, "email": email,
                "firstName": firstname, "lastName": lastname,
                "attributes": {"phoneNumber": phoneNumber},
                "enabled": True,
                "credentials": [{"type": "password", "value": "TemporaryP@ssw0rd123!", "temporary": True}]
            }
            new_user_id = admin_conn.create_user(user_data, exist_ok=False)
            admin_conn.group_user_add(user_id=new_user_id, group_id=group_id_to_assign)
            admin_conn.assign_realm_roles(user_id=new_user_id, roles=[{"id": role_to_assign_obj["id"], "name": role_to_assign_obj["name"]}])
            admin_conn.send_verify_email(user_id=new_user_id)
            logger.info(f"User {email} (ID: {new_user_id}) registered successfully by {token_info.get('preferred_username', 'N/A')}.")
            return redirect(url_for('home', message="User registered successfully! Verification and password update emails sent."))
        except KeycloakGetError as e: # More specific for role/group not found during admin actions
            response_code = getattr(e, 'response_code', 'N/A')
            response_body = getattr(e, 'response_body', str(e))
            logger.error(f"Registration failed (Keycloak resource not found): {response_code} - {response_body}", exc_info=True)
            error_message = f"Registration failed: A required Keycloak resource (e.g., role '{selected_role_name}') was not found."
            return jsonify({"error": error_message}), 400
        except KeycloakError as e: # General Keycloak errors during user creation (e.g., 409 Conflict)
            response_code = getattr(e, 'response_code', 'N/A')
            response_body = getattr(e, 'response_body', str(e))
            error_description = getattr(e, 'error_description', None)
            logger.error(f"Registration failed (KeycloakError): {response_code} - {response_body}", exc_info=True)
            err_msg = "Registration failed: User may already exist." if response_code == 409 else f"Registration failed: {error_description or 'A Keycloak server error occurred.'}"
            return jsonify({"error": err_msg}), (409 if response_code == 409 else 400)
        except Exception as e:
            logger.error(f"Unexpected error during user POST registration: {e}", exc_info=True)
            return jsonify({"error": "Registration failed due to an unexpected error."}), 500

@app.route('/aboutus',methods = ["GET"])
def aboutus():
    return render_template("aboutus.html")

@app.route('/refresh', methods=['GET'])
def refresh_token_route():
    current_refresh_token = session.get('refresh_token')
    if not current_refresh_token:
        logger.warning("Attempt to refresh token without a refresh token in session.")
        delete_user_file()
        return redirect(url_for('logout'))

    keycloak_oidc = get_keycloak_openid()
    try:
        tokens = keycloak_oidc.refresh_token(current_refresh_token)
        session['tokens'] = tokens
        session['access_token'] = tokens['access_token']
        session['refresh_token'] = tokens.get('refresh_token', current_refresh_token)
        logger.info("Token refreshed successfully.")
        return redirect(url_for('home'))
    except KeycloakError as e:
        response_code = getattr(e, 'response_code', 'N/A')
        error_desc = getattr(e, 'error_description', None) or getattr(e, 'response_body', str(e))
        logger.error(f"Refresh token error: {response_code} - {error_desc}", exc_info=True)
        session.clear()
        return redirect(url_for('login', error="Your session has expired or is invalid. Please log in again."))
    except Exception as e:
        logger.error(f"Unexpected error during token refresh: {e}", exc_info=True)
        session.clear()
        return redirect(url_for('login', error="Could not refresh your session due to an unexpected error."))

@app.route('/logout', methods=['GET'])
def logout():
    refresh_token = session.get('refresh_token')
    delete_user_file()
    if refresh_token:
        try:
            keycloak_oidc = get_keycloak_openid()
            keycloak_oidc.logout(refresh_token)
            logger.info("User logged out from Keycloak session.")
        except KeycloakError as e:
            response_code = getattr(e, 'response_code', 'N/A')
            response_body = getattr(e, 'response_body', str(e))
            logger.error(f"Keycloak error during logout: {response_code} - {response_body}", exc_info=True)
        except Exception as e:
            logger.error(f"Error during Keycloak logout: {e}", exc_info=True)

    
    session.clear()
    try:
        # Ensure redirect_uri is allowed in Keycloak client settings
        redirect_uri_logout = url_for('login', _external=True, message="You have been successfully logged out.")
        logout_url_kc = get_keycloak_openid().logout(redirect_uri=redirect_uri_logout)
        return redirect(logout_url_kc)
    except Exception as e:
        logger.error(f"Could not construct Keycloak logout URL: {e}", exc_info=True)
        return redirect(url_for('login', message="You have been logged out."))

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        if not email:
            flash("Lütfen e-posta adresinizi girin.", "warning")
            return render_template("forgot-password.html")

        # 1) Admin token al
        admin_token = get_admin_token()
        if not admin_token:
            flash("Şu anda işlem yapılamıyor. Lütfen daha sonra tekrar deneyin.", "danger")
            return render_template("forgot-password.html")

        # 2) Kullanıcıyı bul
        user_id = find_user_id_by_email(admin_token, email)
        if not user_id:
            flash("Bu e-posta ile bir kullanıcı bulunamadı.", "warning")
            return render_template("forgot-password.html")

        # 3) Reset mailini gönder
        success = send_reset_password_email(
            admin_token=admin_token,
            user_id=user_id,
            client_id=USER_FACING_CLIENT_ID,
            redirect_uri=REDIRECT_URI
        )

        if success:
            flash("Şifre sıfırlama e-postası başarıyla gönderildi.", "success")
            return redirect(url_for("login"))
        else:
            flash("Şifre sıfırlama e-postası gönderilemedi.", "danger")
            return render_template("forgot-password.html")

    # GET
    return render_template("forgot-password.html")

@app.context_processor
def inject_now():
    return {'now': datetime.now()}

@app.route('/connect-calendar')
def connect_calendar():
    if 'access_token' not in session:
        return redirect(url_for('login', error="User not logged in"))

    username = get_session_username()
    if not username:
        return redirect(url_for('login', error="User session not found."))
    
    # Check if we have credentials
    google_creds_doc = db.collection('google_tokens').document(username).get()
    
    if not google_creds_doc.exists:
        # If no credentials, redirect to authorize
        session['google_auth_redirect_uri'] = request.referrer or url_for('home')
        return redirect(url_for('authorize_google'))

    # If we have credentials, just show the calendar (frontend will handle it)
    return redirect(url_for('home'))

@app.route('/authorize-google')
def authorize_google():
    access_token = session.get('access_token')
    if not access_token:
        return redirect(url_for('login'))
        
    username = get_session_username()
    if not username:
        return redirect(url_for('login', error="User session not found."))
    
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return "Google Client ID or Secret is not configured on the server.", 500

    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [GOOGLE_REDIRECT_URI]
            }
        },
        scopes=GOOGLE_CALENDAR_SCOPES,
        redirect_uri=GOOGLE_REDIRECT_URI
    )

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        prompt='consent' # force to get a refresh token
    )
    
    session['google_oauth_state'] = state
    return redirect(authorization_url)

@app.route('/google-callback')
def google_callback():
    state = session.pop('google_oauth_state', None)

    if state is not None and state != request.args.get('state'):
        logger.warning("State mismatch. Possible CSRF attack. State from session: %s, state from request: %s", state, request.args.get('state'))
        return 'State mismatch. Possible CSRF attack.', 400

    username = get_session_username()
    if not username:
        return redirect(url_for('login', error="User session not found after Google auth."))

    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return "Google Client ID or Secret is not configured on the server.", 500
        
    flow = Flow.from_client_config(
         {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [GOOGLE_REDIRECT_URI]
            }
        },
        scopes=GOOGLE_CALENDAR_SCOPES,
        redirect_uri=GOOGLE_REDIRECT_URI
    )

    try:
        # Use the full URL for the authorization response
        authorization_response = request.url
        # In some environments (like behind a proxy), the scheme might be http, but Google requires https
        if not authorization_response.startswith("https"):
             authorization_response = authorization_response.replace("http://", "https://", 1)

        flow.fetch_token(authorization_response=authorization_response)
    except Exception as e:
        logger.error("Failed to fetch Google token: %s", e, exc_info=True)
        return "Failed to fetch Google token. Please try again.", 500


    credentials = flow.credentials
    
    # Store credentials in Firestore, linked to the Keycloak username
    try:
        db.collection('google_tokens').document(username).set({
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        })
        logger.info(f"Successfully stored Google tokens for user: {username}")
    except Exception as e:
        logger.error(f"Failed to store Google tokens in Firestore for user {username}: {e}", exc_info=True)
        return "Could not save your Google authorization. Please try again.", 500
    
    redirect_uri = session.pop('google_auth_redirect_uri', url_for('home'))
    return redirect(redirect_uri)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)