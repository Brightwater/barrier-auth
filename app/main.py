
from datetime import timedelta, datetime, timezone
import secrets
import string
from fastapi import Depends, FastAPI, HTTPException, Request, status
import uvicorn
from model.pydantics import *
from utility.database import database
from passlib.context import CryptContext
from fastapi.concurrency import run_in_threadpool
import json
import jwt
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware

SECRET_KEY = "bacf65e28bc0cb9e2e9473f899a31fb340de991bdf63be9c8d10157f8afb3121"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins="*",
    allow_methods=["*"],
    allow_headers=["*"],
)

# to run the app  uvicorn main:app --reload --port 4344 --host 0.0.0.0
def getPasswordHash(password):
    return pwd_context.hash(password)

def verifyPassword(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def createJwt(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    # encode the jwt using pyjwt
    # encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.on_event("startup")
async def startup():
    await database.connect()
    
@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

# @app.get("/")
# async def root():
#     # query = "select * from authenticated_user"
#     query = f"select username, encrypted_refresh_token as refresh, scopes from authenticated_user where username = 'abc'"

#     data = await database.fetch_all(query)
#     return data

@app.post("/login/")
async def login(user: User):
    # return "OK"
    d = await database.fetch_all(f"select username, password from authenticated_user where username = '{user.username}'")
    if not await run_in_threadpool(lambda: verifyPassword(user.password, d[0].password)):  # type: ignore
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    refreshToken = await run_in_threadpool(lambda: ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(20)))
    encodedRefreshToken = await run_in_threadpool(lambda: getPasswordHash(refreshToken))
    expireTime = round(datetime.now(timezone.utc).timestamp()) + 87600 * REFRESH_TOKEN_EXPIRE_DAYS
    
    
    
    oldRefreshTokens = await database.fetch_one(f"""select refresh_token_data from authenticated_user where username = '{user.username}'""")

    if oldRefreshTokens['refresh_token_data'] == None:
        oldRefreshTokens = []
    else:
        oldRefreshTokens = json.loads(oldRefreshTokens['refresh_token_data'])
    oldRefreshTokens: list = oldRefreshTokens
    oldRefreshTokens.append({"encrypted_refresh_token": encodedRefreshToken, 'refresh_token_expiration': expireTime})
    
    response = {'username':user.username ,'refreshToken': refreshToken, 'exp': expireTime, "tokenIndex": len(oldRefreshTokens)-1}
   
    await database.execute(f"""update authenticated_user 
                               set refresh_token_data = '{json.dumps(oldRefreshTokens)}'
                               where username = '{user.username}'""")

    # await database.execute(f"update authenticated_user set encrypted_refresh_token = '{encodedRefreshToken}', refresh_token_expiration = to_timestamp({expireTime}) where username = '{user.username}'")
    return response

@app.post("/createUser/")
async def login3(user: User):
    hashedPassword = await run_in_threadpool(lambda: getPasswordHash(user.password))
    userVal = {"username": user.username, "password": hashedPassword}
    
    insert = f"insert into authenticated_user values(:username, :password)"
    return await database.execute(insert, values=userVal)

@app.post("/createUser/Recipe")
async def login4(request: Request, user: User):
    # get the origin of the request
    domain = request.headers.get('Origin')
    print(domain)
    
    if (domain != 'https://courtmew.recipe.bright-waters.com'):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This request domain is not allowed for the scope",
            headers={"WWW-Authenticate": "Bearer"},
        ) 
    
    hashedPassword = await run_in_threadpool(lambda: getPasswordHash(user.password))
    
    # test scope is for recipes
    userVal = {"username": user.username, "password": hashedPassword, "scopes": ["test"]}
    insert = f"insert into authenticated_user values(:username, :password, :scopes)"
    return await database.execute(insert, values=userVal)

@app.post("/login/token")
async def loginToken(user: User, tokenIndex: int):
    # dUser = await database.fetch_all(f"select username, encrypted_refresh_token as refresh, extract(epoch from refresh_token_expiration) as exp, scopes from authenticated_user where username = '{user.username}'")
    ret = await database.fetch_all(f"select username, refresh_token_data, scopes from authenticated_user where username = '{user.username}'")
    refreshData = json.loads(ret[0]['refresh_token_data'])
    dUser = {'username': ret[0]['username'], 'refresh': refreshData[tokenIndex]['encrypted_refresh_token'], 'exp': refreshData[tokenIndex]['refresh_token_expiration'], 'scopes': ret[0]['scopes']}
  
    if not dUser['exp'] or round(dUser['exp']) <= round(datetime.now(timezone.utc).timestamp()):  # type: ignore
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired, please login again",
            headers={"WWW-Authenticate": "Bearer"},
        ) 
    if not await run_in_threadpool(lambda: verifyPassword(user.password, dUser['refresh'])):  # type: ignore
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = createJwt(
        data={"username": user.username, "scopes": dUser['scopes']}, expires_delta=access_token_expires  # type: ignore
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/verifyToken")
async def get_current_user(token):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("username")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except Exception:
        raise credentials_exception
    
    user = await database.fetch_all(f"select username, password from authenticated_user where username = '{token_data.username}'")
    if user is None:
        raise credentials_exception
    
    return user[0]

@app.post("/verifyTokenAndScope")
async def get_current_user_and_scope(token: str, scope: str):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("username")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except Exception:
        raise credentials_exception
    
    user = await database.fetch_all(f"select username, password, scopes from authenticated_user where username = '{token_data.username}'")
    if user is None:
        raise credentials_exception
    
    user = user[0]
    
    for s in user['scopes']:
        if s == scope:
            return user[0]
    
    raise credentials_exception