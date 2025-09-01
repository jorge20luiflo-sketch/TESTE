from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from jose import JWTError, jwt
from passlib.context import CryptContext

# -------------------- Configs/JWT --------------------
SECRET_KEY = "ABFD-EFG-HIJ"  
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# -------------------- DB Setup -----------------------
DATABASE_URL = "sqlite:///./usuarios.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# -------------------- Modelos ORM --------------------
class UsuarioDB(Base):
    __tablename__ = "usuarios"
    id = Column(Integer, primary_key=True, index=True)
    usuario = Column(String, unique=True, index=True, nullable=False)
    nome = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)

Base.metadata.create_all(bind=engine)

# -------------------- Schemas Pydantic --------------------
class UsuarioCreate(BaseModel):
    usuario: str
    nome: str
    email: EmailStr
    senha: str

class UsuarioUpdate(BaseModel):
    nome: Optional[str] = None
    email: Optional[EmailStr] = None
    senha: Optional[str] = None

class UsuarioOut(BaseModel):
    id: int
    usuario: str
    nome: str
    email: EmailStr
    class Config:
        from_attributes = True  # pydantic v2

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    sub: Optional[str] = None  # username (usuario)

# -------------------- Segurança (hash/verify + JWT) --------------------
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user_by_username(db: Session, username: str) -> Optional[UsuarioDB]:
    return db.query(UsuarioDB).filter(UsuarioDB.usuario == username).first()

def authenticate_user(db: Session, username: str, password: str) -> Optional[UsuarioDB]:
    user = get_user_by_username(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> UsuarioDB:
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Não autenticado",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exc
        token_data = TokenData(sub=username)
    except JWTError:
        raise credentials_exc
    user = get_user_by_username(db, token_data.sub)
    if user is None:
        raise credentials_exc
    return user

# -------------------- FastAPI App --------------------
app = FastAPI(title="API de Usuários")

# --------- Auth: obter token (login) ----------
@app.post("/token", response_model=Token, summary="Login e obtenção de token JWT")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # OAuth2PasswordRequestForm usa campos: username, password
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Usuário ou senha inválidos")
    access_token = create_access_token(data={"sub": user.usuario})
    return {"access_token": access_token, "token_type": "bearer"}

# --------- Cadastro (público) ----------
@app.post("/usuarios/", response_model=UsuarioOut, status_code=201, summary="Criar novo usuário")
def criar_usuario(payload: UsuarioCreate, db: Session = Depends(get_db)):
    if db.query(UsuarioDB).filter(UsuarioDB.usuario == payload.usuario).first():
        raise HTTPException(status_code=400, detail="Usuário já existe")
    if db.query(UsuarioDB).filter(UsuarioDB.email == payload.email).first():
        raise HTTPException(status_code=400, detail="E-mail já cadastrado")

    user = UsuarioDB(
        usuario=payload.usuario,
        nome=payload.nome,
        email=payload.email,
        hashed_password=get_password_hash(payload.senha),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

# --------- Rotas protegidas ----------
@app.get("/usuarios/", response_model=List[UsuarioOut], summary="Listar usuários (protegido)")
def listar_usuarios(current_user: UsuarioDB = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(UsuarioDB).all()

@app.get("/usuarios/me", response_model=UsuarioOut, summary="Meu perfil (protegido)")
def meu_perfil(current_user: UsuarioDB = Depends(get_current_user)):
    return current_user

@app.get("/usuarios/{user_id}", response_model=UsuarioOut, summary="Buscar usuário por ID (protegido)")
def buscar_usuario(user_id: int, current_user: UsuarioDB = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(UsuarioDB).filter(UsuarioDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    return user

@app.put("/usuarios/{user_id}", response_model=UsuarioOut, summary="Atualizar usuário (protegido)")
def atualizar_usuario(user_id: int, payload: UsuarioUpdate, current_user: UsuarioDB = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(UsuarioDB).filter(UsuarioDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    if payload.nome is not None:
        user.nome = payload.nome
    if payload.email is not None:
        # checar duplicidade de email
        exists = db.query(UsuarioDB).filter(UsuarioDB.email == payload.email, UsuarioDB.id != user_id).first()
        if exists:
            raise HTTPException(status_code=400, detail="E-mail já cadastrado por outro usuário")
        user.email = payload.email
    if payload.senha is not None:
        user.hashed_password = get_password_hash(payload.senha)

    db.commit()
    db.refresh(user)
    return user

@app.delete("/usuarios/{user_id}", summary="Deletar usuário (protegido)")
def deletar_usuario(user_id: int, current_user: UsuarioDB = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(UsuarioDB).filter(UsuarioDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    db.delete(user)
    db.commit()
    return {"message": "Usuário deletado com sucesso"}
