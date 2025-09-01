from fastapi import FastAPI

# Criar aplicação FastAPI
app = FastAPI()

# Rota inicial GET
@app.get("/")
def read_root():
    return {"message": "Olá criei minha primeira API"}

# Rota GET com parâmetro
@app.get("/ExibeNome/{name}")
def read_item(name: str):
    return {"message": f"Olá, {name}!"}
