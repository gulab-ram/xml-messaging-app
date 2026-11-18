from fastapi import FastAPI, APIRouter, Depends, HTTPException, status, Response, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
from datetime import datetime, timezone, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from pathlib import Path
import os
import uuid
import logging
import base64

# Crypto
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asy_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

# XML
from lxml import etree
import xmlschema

# ------------------------------------------------------
# Environment & App Setup
# ------------------------------------------------------
ROOT_DIR = Path(__file__).parent
from dotenv import load_dotenv
load_dotenv(ROOT_DIR / '.env')

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db_name = os.environ['DB_NAME']
db = client[db_name]

app = FastAPI()
api_router = APIRouter(prefix="/api")

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ------------------------------------------------------
# Helpers & Constants
# ------------------------------------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
JWT_ALG = "HS256"
JWT_EXP_MIN = 60 * 24  # 24 hours

XSD_SCHEMA_STR = r"""<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" elementFormDefault="qualified" attributeFormDefault="unqualified">
  <xs:element name="Envelope">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="Header" minOccurs="0">
          <xs:complexType>
            <xs:sequence>
              <xs:element name="SchemaVersion" type="xs:string" minOccurs="0" />
            </xs:sequence>
          </xs:complexType>
        </xs:element>
        <xs:element name="Body">
          <xs:complexType>
            <xs:sequence>
              <xs:element name="Message">
                <xs:complexType>
                  <xs:sequence>
                    <xs:element name="MessageId" type="xs:string" />
                    <xs:element name="Sender" type="xs:string" />
                    <xs:element name="Recipient" type="xs:string" />
                    <xs:element name="Timestamp" type="xs:string" />
                    <xs:element name="ReplyTo" type="xs:string" minOccurs="0" />
                    <xs:element name="Cipher">
                      <xs:complexType>
                        <xs:sequence>
                          <xs:element name="Algorithm" type="xs:string" />
                          <xs:element name="IV" type="xs:string" />
                          <xs:element name="Ciphertext" type="xs:string" />
                        </xs:sequence>
                      </xs:complexType>
                    </xs:element>
                    <xs:element name="Metadata" type="xs:string" minOccurs="0" />
                    <xs:element name="Signature">
                      <xs:complexType>
                        <xs:sequence>
                          <xs:element name="SignatureValue" type="xs:string" />
                        </xs:sequence>
                        <xs:attribute name="Algorithm" type="xs:string" use="required" />
                      </xs:complexType>
                    </xs:element>
                  </xs:sequence>
                </xs:complexType>
              </xs:element>
            </xs:sequence>
          </xs:complexType>
        </xs:element>
      </xs:sequence>
    </xs:complexType>
  </xs:element>
</xs:schema>"""

XSD_SCHEMA = xmlschema.XMLSchema(XSD_SCHEMA_STR)

# ------------------------------------------------------
# Key Management
# ------------------------------------------------------
async def get_or_create_app_keys():
    doc = await db.keys.find_one({"_id": "app_keys"})
    if doc:
        jwt_secret = doc["jwt_secret"].encode()
        private_key = serialization.load_pem_private_key(doc["rsa_private_pem"].encode(), password=None, backend=default_backend())
        public_key = serialization.load_pem_public_key(doc["rsa_public_pem"].encode(), backend=default_backend())
        return jwt_secret, private_key, public_key

    jwt_secret = base64.urlsafe_b64encode(os.urandom(32))
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    await db.keys.update_one(
        {"_id": "app_keys"},
        {"$set": {"jwt_secret": jwt_secret.decode(), "rsa_private_pem": private_pem.decode(), "rsa_public_pem": public_pem.decode(), "created_at": datetime.now(timezone.utc).isoformat()}},
        upsert=True
    )
    return jwt_secret, private_key, public_key

JWT_SECRET: Optional[bytes] = None
RSA_PRIVATE = None
RSA_PUBLIC = None

# ------------------------------------------------------
# Models
# ------------------------------------------------------
class StatusCheck(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    client_name: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class StatusCheckCreate(BaseModel):
    client_name: str

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class UserOut(BaseModel):
    id: str
    username: str
    email: EmailStr
    created_at: str

class UserProfileUpdate(BaseModel):
    email: Optional[EmailStr] = None
    current_password: Optional[str] = None
    new_password: Optional[str] = None

class MessageSendInput(BaseModel):
    recipient: str
    body: str
    metadata: Optional[str] = None
    reply_to: Optional[str] = None

class MessageListItem(BaseModel):
    id: str
    sender: str
    recipient: str
    created_at: str
    signature_valid: bool
    is_read: bool = False
    reply_to: Optional[str] = None

class MessageDetail(BaseModel):
    id: str
    xml: str

class DecryptResponse(BaseModel):
    id: str
    plaintext: str

class UnreadCountResponse(BaseModel):
    count: int

# ------------------------------------------------------
# Utility functions
# ------------------------------------------------------
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def make_jwt(user_id: str, username: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXP_MIN)
    payload = {"sub": user_id, "username": username, "exp": int(exp.timestamp()), "iat": int(datetime.now(timezone.utc).timestamp())}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def parse_jwt(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

def aes_encrypt_256_cbc(plaintext: bytes, key: bytes):
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv, encryptor.update(padded) + encryptor.finalize()

def aes_decrypt_256_cbc(iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def rsa_sign(data: bytes) -> bytes:
    return RSA_PRIVATE.sign(data, asy_padding.PKCS1v15(), hashes.SHA256())

def rsa_verify(data: bytes, signature: bytes) -> bool:
    try:
        RSA_PUBLIC.verify(signature, data, asy_padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False

def build_message_xml(message_id, sender, recipient, timestamp_iso, iv_b64, ct_b64, metadata, signature_b64, reply_to=None) -> str:
    envelope = etree.Element("Envelope")
    header = etree.SubElement(envelope, "Header")
    etree.SubElement(header, "SchemaVersion").text = "1.0"
    body = etree.SubElement(envelope, "Body")
    msg = etree.SubElement(body, "Message")
    etree.SubElement(msg, "MessageId").text = message_id
    etree.SubElement(msg, "Sender").text = sender
    etree.SubElement(msg, "Recipient").text = recipient
    etree.SubElement(msg, "Timestamp").text = timestamp_iso
    if reply_to:
        etree.SubElement(msg, "ReplyTo").text = reply_to
    cipher_el = etree.SubElement(msg, "Cipher")
    etree.SubElement(cipher_el, "Algorithm").text = "AES-256-CBC"
    etree.SubElement(cipher_el, "IV").text = iv_b64
    etree.SubElement(cipher_el, "Ciphertext").text = ct_b64
    if metadata and metadata.strip():
        etree.SubElement(msg, "Metadata").text = metadata
    sig_el = etree.SubElement(msg, "Signature")
    sig_el.set("Algorithm", "RSA-SHA256")
    etree.SubElement(sig_el, "SignatureValue").text = signature_b64
    return etree.tostring(envelope, pretty_print=True, encoding='utf-8', xml_declaration=True).decode()

def extract_signing_string(message_id, sender, recipient, timestamp_iso, iv_b64, ct_b64, metadata, reply_to=None) -> bytes:
    parts = [message_id, sender, recipient, timestamp_iso, iv_b64, ct_b64, metadata or "", reply_to or ""]
    return "|".join(parts).encode('utf-8')

async def verify_and_list(items: list) -> List[MessageListItem]:
    result = []
    for it in items:
        try:
            root = etree.fromstring(it["xml"].encode())
            ct_b64 = root.find('.//Ciphertext').text
        except Exception:
            ct_b64 = ""
        signing_bytes = extract_signing_string(it["id"], it["sender"], it["recipient"], it["created_at"], it["iv_b64"], ct_b64, it.get("metadata", ""), it.get("reply_to"))
        sig_ok = rsa_verify(signing_bytes, base64.b64decode(it["signature_b64"]))
        result.append(MessageListItem(id=it["id"], sender=it["sender"], recipient=it["recipient"], created_at=it["created_at"], signature_valid=sig_ok, is_read=it.get("is_read", False), reply_to=it.get("reply_to")))
    return result

async def seed_demo_users():
    await db.users.create_index("username", unique=True)
    await db.users.create_index("email", unique=True)
    for u in [{"username": "alice", "email": "alice@example.com", "password": "alice123"}, {"username": "bob", "email": "bob@example.com", "password": "bob123"}]:
        if not await db.users.find_one({"username": u["username"]}):
            await db.users.insert_one({"id": str(uuid.uuid4()), "username": u["username"], "email": u["email"], "password_hash": hash_password(u["password"]), "created_at": datetime.now(timezone.utc).isoformat()})

async def ensure_collections():
    await db.messages.create_index("recipient")
    await db.messages.create_index("sender")
    await db.messages.create_index("reply_to")

# ------------------------------------------------------
# Dependencies
# ------------------------------------------------------
async def get_current_user(request: Request) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Missing auth token")
    payload = parse_jwt(token)
    user = await db.users.find_one({"id": payload["sub"]})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# ------------------------------------------------------
# Routes
# ------------------------------------------------------
@api_router.get("/")
async def root():
    return {"message": "Secure XML Messaging API"}

@api_router.post("/status", response_model=StatusCheck)
async def create_status_check(input: StatusCheckCreate):
    status_obj = StatusCheck(client_name=input.client_name)
    await db.status_checks.insert_one(status_obj.model_dump())
    return status_obj

@api_router.get("/status", response_model=List[StatusCheck])
async def get_status_checks():
    checks = await db.status_checks.find().to_list(1000)
    return [StatusCheck(**{k: v for k, v in sc.items() if k != "_id"}) for sc in checks]

# ---- Auth ----
@api_router.post("/auth/register", response_model=UserOut)
async def register(input: UserCreate):
    if await db.users.find_one({"$or": [{"username": input.username}, {"email": input.email}]}):
        raise HTTPException(status_code=400, detail="Username or email already exists")
    user_id = str(uuid.uuid4())
    doc = {"id": user_id, "username": input.username, "email": str(input.email), "password_hash": hash_password(input.password), "created_at": datetime.now(timezone.utc).isoformat()}
    await db.users.insert_one(doc)
    return UserOut(id=user_id, username=input.username, email=input.email, created_at=doc["created_at"])

@api_router.post("/auth/login")
async def login(input: UserLogin, response: Response):
    user = await db.users.find_one({"username": input.username})
    if not user or not verify_password(input.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = make_jwt(user_id=user["id"], username=user["username"])
    response.set_cookie(key="access_token", value=token, httponly=True, secure=True, samesite="none", max_age=JWT_EXP_MIN * 60)
    return {"ok": True}

@api_router.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie("access_token")
    return {"ok": True}

@api_router.get("/auth/me", response_model=UserOut)
async def me(user=Depends(get_current_user)):
    return UserOut(id=user["id"], username=user["username"], email=user["email"], created_at=user["created_at"])

@api_router.patch("/auth/profile", response_model=UserOut)
async def update_profile(input: UserProfileUpdate, user=Depends(get_current_user)):
    updates = {}
    if input.email:
        if await db.users.find_one({"email": str(input.email), "id": {"$ne": user["id"]}}):
            raise HTTPException(status_code=400, detail="Email already in use")
        updates["email"] = str(input.email)
    if input.new_password:
        if not input.current_password or not verify_password(input.current_password, user["password_hash"]):
            raise HTTPException(status_code=400, detail="Current password is incorrect")
        updates["password_hash"] = hash_password(input.new_password)
    if not updates:
        raise HTTPException(status_code=400, detail="Nothing to update")
    await db.users.update_one({"id": user["id"]}, {"$set": updates})
    updated = await db.users.find_one({"id": user["id"]})
    return UserOut(id=updated["id"], username=updated["username"], email=updated["email"], created_at=updated["created_at"])

@api_router.get("/users")
async def list_users(user=Depends(get_current_user)):
    users = await db.users.find({"id": {"$ne": user["id"]}}, {"username": 1, "_id": 0}).to_list(100)
    return [u["username"] for u in users]

# ---- Messages ----
@api_router.get("/messages/schema")
async def get_schema():
    from fastapi.responses import Response as FR
    return FR(content=XSD_SCHEMA_STR, media_type="application/xml")

@api_router.get("/messages/unread-count", response_model=UnreadCountResponse)
async def unread_count(user=Depends(get_current_user)):
    count = await db.messages.count_documents({"recipient": user["username"], "is_read": False})
    return UnreadCountResponse(count=count)

@api_router.post("/messages/send", response_model=MessageDetail)
async def send_message(input: MessageSendInput, user=Depends(get_current_user)):
    if not await db.users.find_one({"username": input.recipient}):
        raise HTTPException(status_code=404, detail="Recipient not found")
    if input.reply_to and not await db.messages.find_one({"id": input.reply_to}):
        raise HTTPException(status_code=404, detail="Parent message not found")

    message_id = str(uuid.uuid4())
    timestamp_iso = datetime.now(timezone.utc).isoformat()
    aes_key = os.urandom(32)
    iv, ciphertext = aes_encrypt_256_cbc(input.body.encode('utf-8'), aes_key)
    iv_b64 = base64.b64encode(iv).decode()
    ct_b64 = base64.b64encode(ciphertext).decode()
    signing_bytes = extract_signing_string(message_id, user["username"], input.recipient, timestamp_iso, iv_b64, ct_b64, input.metadata, input.reply_to)
    signature_b64 = base64.b64encode(rsa_sign(signing_bytes)).decode()
    xml_str = build_message_xml(message_id, user["username"], input.recipient, timestamp_iso, iv_b64, ct_b64, input.metadata, signature_b64, input.reply_to)

    try:
        XSD_SCHEMA.validate(xml_str)
    except xmlschema.validators.exceptions.XMLSchemaValidationError as e:
        raise HTTPException(status_code=400, detail=f"XML schema error: {str(e)}")

    await db.messages.insert_one({"id": message_id, "sender": user["username"], "recipient": input.recipient, "xml": xml_str, "aes_key_b64": base64.b64encode(aes_key).decode(), "iv_b64": iv_b64, "signature_b64": signature_b64, "created_at": timestamp_iso, "metadata": input.metadata or "", "reply_to": input.reply_to, "is_read": False})
    return MessageDetail(id=message_id, xml=xml_str)

@api_router.get("/messages/inbox", response_model=List[MessageListItem])
async def inbox(user=Depends(get_current_user), search: Optional[str] = None, date_from: Optional[str] = None, date_to: Optional[str] = None):
    query: dict = {"recipient": user["username"]}
    if search:
        query["sender"] = {"$regex": search, "$options": "i"}
    if date_from:
        query.setdefault("created_at", {})["$gte"] = date_from
    if date_to:
        query.setdefault("created_at", {})["$lte"] = date_to + "Z"
    items = await db.messages.find(query).sort("created_at", -1).to_list(200)
    return await verify_and_list(items)

@api_router.get("/messages/sent", response_model=List[MessageListItem])
async def sent_box(user=Depends(get_current_user), search: Optional[str] = None, date_from: Optional[str] = None, date_to: Optional[str] = None):
    query: dict = {"sender": user["username"]}
    if search:
        query["recipient"] = {"$regex": search, "$options": "i"}
    if date_from:
        query.setdefault("created_at", {})["$gte"] = date_from
    if date_to:
        query.setdefault("created_at", {})["$lte"] = date_to + "Z"
    items = await db.messages.find(query).sort("created_at", -1).to_list(200)
    return await verify_and_list(items)

@api_router.get("/messages/{message_id}/thread", response_model=List[MessageListItem])
async def get_thread(message_id: str, user=Depends(get_current_user)):
    items = await db.messages.find({"reply_to": message_id}).sort("created_at", 1).to_list(200)
    accessible = [it for it in items if it["sender"] == user["username"] or it["recipient"] == user["username"]]
    return await verify_and_list(accessible)

@api_router.get("/messages/{message_id}", response_model=MessageDetail)
async def get_message(message_id: str, user=Depends(get_current_user)):
    it = await db.messages.find_one({"id": message_id, "$or": [{"sender": user["username"]}, {"recipient": user["username"]}]})
    if not it:
        raise HTTPException(status_code=404, detail="Message not found")
    if it["recipient"] == user["username"] and not it.get("is_read", False):
        await db.messages.update_one({"id": message_id}, {"$set": {"is_read": True}})
    return MessageDetail(id=it["id"], xml=it["xml"])

@api_router.patch("/messages/{message_id}/read")
async def mark_read(message_id: str, user=Depends(get_current_user)):
    it = await db.messages.find_one({"id": message_id, "recipient": user["username"]})
    if not it:
        raise HTTPException(status_code=404, detail="Message not found")
    await db.messages.update_one({"id": message_id}, {"$set": {"is_read": True}})
    return {"ok": True}

@api_router.post("/messages/{message_id}/decrypt", response_model=DecryptResponse)
async def decrypt_message(message_id: str, user=Depends(get_current_user)):
    it = await db.messages.find_one({"id": message_id, "$or": [{"sender": user["username"]}, {"recipient": user["username"]}]})
    if not it:
        raise HTTPException(status_code=404, detail="Message not found")
    if it["recipient"] == user["username"] and not it.get("is_read", False):
        await db.messages.update_one({"id": message_id}, {"$set": {"is_read": True}})
    aes_key = base64.b64decode(it["aes_key_b64"])
    iv = base64.b64decode(it["iv_b64"])
    try:
        root = etree.fromstring(it["xml"].encode())
        ct_b64 = root.find('.//Ciphertext').text
    except Exception:
        raise HTTPException(status_code=400, detail="Malformed XML")
    plaintext = aes_decrypt_256_cbc(iv, base64.b64decode(ct_b64), aes_key)
    return DecryptResponse(id=message_id, plaintext=plaintext.decode('utf-8'))

@api_router.delete("/messages/{message_id}")
async def delete_message(message_id: str, user=Depends(get_current_user)):
    it = await db.messages.find_one({"id": message_id, "$or": [{"sender": user["username"]}, {"recipient": user["username"]}]})
    if not it:
        raise HTTPException(status_code=404, detail="Message not found")
    await db.messages.delete_one({"id": message_id})
    return {"ok": True}

app.include_router(api_router)

@app.on_event("startup")
async def on_startup():
    global JWT_SECRET, RSA_PRIVATE, RSA_PUBLIC
    JWT_SECRET, RSA_PRIVATE, RSA_PUBLIC = await get_or_create_app_keys()
    await seed_demo_users()
    await ensure_collections()
    logger.info("Startup complete.")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
