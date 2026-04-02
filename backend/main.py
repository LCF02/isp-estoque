import smtplib
from email.mime.text import MIMEText
import secrets
from datetime import datetime, timedelta
from fastapi import FastAPI
from sqlalchemy import create_engine, text
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
import os

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# MODELS
class UsuarioCadastro(BaseModel):
    nome: str
    email: str
    senha: str


class UsuarioLogin(BaseModel):
    email: str
    senha: str

class RecuperarSenha(BaseModel):
    email: str

class ResetarSenha(BaseModel):
    token: str
    senha: str


def enviar_email(destino, link):
    remetente = os.getenv("EMAIL_USER")
    senha = os.getenv("EMAIL_PASS")
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT"))


    msg = MIMEMultipart()
    msg["From"] = remetente
    msg["To"] = destino
    msg["Subject"] = "Redefinição de Senha"

    corpo = f"""
Olá,

Clique no link abaixo para redefinir sua senha:

{link}

Se você não solicitou, ignore este email.
"""

    msg.attach(MIMEText(corpo, "plain", "utf-8"))

    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(remetente, senha)

    server.sendmail(remetente, destino, msg.as_string())
    server.quit()

# Rota teste
@app.get("/")
def home():
    return {"status": "API rodando"}


# Cadastro
@app.post("/cadastro")
def cadastro(usuario: UsuarioCadastro):
    senha_hash = pwd_context.hash(usuario.senha)

    try:
        with engine.connect() as conn:
            conn.execute(text("""
                INSERT INTO usuarios (nome, email, senha)
                VALUES (:nome, :email, :senha)
            """), {
                "nome": usuario.nome,
                "email": usuario.email,
                "senha": senha_hash
            })
            conn.commit()

        return {"msg": "usuario criado"}

    except Exception as e:
        return {"erro": str(e)}


# Login
@app.post("/login")
def login(usuario: UsuarioLogin):

    with engine.connect() as conn:
        result = conn.execute(text("""
            SELECT * FROM usuarios WHERE email = :login OR nome = :login
        """), {"login": usuario.email}).fetchone()

    if not result:
        return {"erro": "usuario não encontrado"}

    senha_valida = pwd_context.verify(usuario.senha, result.senha)

    if not senha_valida:
        return {"erro": "senha incorreta"}

    return {"msg": "login realizado"}

#Esqueci minha senha
@app.post("/esqueci-senha")
def esqueci_senha(dados: RecuperarSenha):

    token = secrets.token_urlsafe(32)
    expira = datetime.utcnow() + timedelta(minutes=15)

    with engine.begin() as conn:
        result = conn.execute(text("""
            SELECT * FROM usuarios WHERE email = :email
        """), {"email": dados.email}).fetchone()

        if not result:
            return {"erro": "Email não encontrado"}

        conn.execute(text("""
            UPDATE usuarios 
            SET token_reset = :token, token_expira = :expira
            WHERE email = :email
        """), {
            "token": token,
            "expira": expira,
            "email": dados.email
        })

    link = f"http://127.0.0.1:3306/frontend/resetar-senha?token={token}"
    print("LINK GERADO:", link)

    enviar_email(dados.email, link)

    return {"msg": "Link enviado para seu email"}

@app.post("/resetar-senha")
def resetar_senha(dados: ResetarSenha):

    senha_hash = pwd_context.hash(dados.senha)

    with engine.begin() as conn:
        result = conn.execute(text("""
            SELECT * FROM usuarios 
            WHERE token_reset = :token
            AND token_expira > NOW()
        """), {"token": dados.token}).fetchone()

        if not result:
            return {"erro": "Token inválido ou expirado"}

        conn.execute(text("""
            UPDATE usuarios 
            SET senha = :senha,
                token_reset = NULL,
                token_expira = NULL
            WHERE token_reset = :token
        """), {
            "senha": senha_hash,
            "token": dados.token
        })

    return {"msg": "Senha redefinida com sucesso"}