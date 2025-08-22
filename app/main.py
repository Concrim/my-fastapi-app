from dataclasses import field
from fastapi import FastAPI, Path, HTTPException, Query, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse,FileResponse
from typing import Optional, Dict,Annotated,List
from pydantic import BaseModel, Field, field_validator, model_validator, computed_field
import json
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from app.data import db
import os
from dotenv import load_dotenv

################################################ SECURITY ####################################################
SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-key")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-key")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')

app = FastAPI()


class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str or None = None

class User(BaseModel):
    username: str
    fullname: str or None = None
    email: str or None = None
    disabled: bool or None = None

class UserInDB(User):
    hashed_password: str
# Modeling


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username: str):
    if username in db:
        user_data = db[username]
        return UserInDB(**user_data)

def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                          detail="Could not validate credentials",)
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception

    user = get_user(db, token_data.username)
    if user is None:
        raise credentials_exception

    return user

async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username},
                                       expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

# ################################## SECURITY ####################################################

class Book(BaseModel):
    id: Annotated[int, Field(...,gt=0, description="id of the book")]
    # field can be used for constraints and to attach metadata
    title: Annotated[str, Field(...,min_length=5, max_length=50, title="Title",
                                description="The title of the book",examples = ["Atomic Habits","The Messenger Bird"])]
    author: Annotated[str, Field(...,description="Author of the book")]
    year: Annotated[int, Field(...,gt=1950, strict=True, description="Year of release")] # strict disallows type-coercion
    genre: Optional[List[str]] = None
    rating: Optional[float] = None

    # using field validators
    # can be used to validate custom inputs
    # can be used to transform the input, e.g. Make the value uppercase
    @field_validator("title")
    @classmethod
    def transform_title(cls, value):
        return value.upper()

    # before and after in field_validators
    @field_validator("rating", mode="after") # after uses the value before type coercion, before used the value before coercion
    @classmethod
    def validate_rating(cls, value):
        if value is None:
            return value
        if 0 < value <= 5:
            return value
        raise HTTPException(status_code=400, detail="Rating must be between 0 and 5")

    @model_validator(mode="after")
    def check_rating(cls,model):
        if model.year < 2000 and model.rating is None:
            raise HTTPException(status_code=400, detail="Old books must have a rating.")
        return model

    @computed_field
    @property
    def age(self) -> int:
        return 2025 - self.year

    @computed_field
    @property
    def antique(self) -> str:
        if self.age > 25:
            return "This book is an antique."
        return "Not an antique."

class UpdateBook(BaseModel):
    genre: Optional[List[str]] = None
    rating: Optional[Annotated[float, Field(gt=0, le=5)]] = None


data = {
    "id": 1,
    "title": "Atomic Habits",
    "author": "James Clear",
    "year": 1998,
    "genre": ["Self-help"],
    "rating": 4.0
  }

# You can also use a model as the datatype


# CODE

def load_books():
    with open("books.json") as f:
        books = json.load(f)
    return books

def save_books(data):
    with open("books.json", "w") as f:
        json.dump(data, f)

# DEPENDENCIES
def load_data():
    with open('books.json') as f:
        books = json.load(f)
    return books


@app.get('/')  # simple endpoint
def home():
    return {'message': 'Hello World'}


@app.get('/books')  # returning all books
def get_books(books=Depends(load_books),user=Depends(get_current_user)):
    return books


@app.get('/books/{book_id}')  # returning an individual book
def get_book(book_id: str,books=Depends(load_books),user=Depends(get_current_user)):
    if book_id not in books:
        raise HTTPException(status_code=404, detail='Book not found.')
    book = books[book_id]
    return f'{book["title"]} by {book["author"]}'


# Adding a book
@app.post('/add_book')
def add_book(book: Book,books=Depends(load_books), user=Depends(get_current_user)):
    if str(book.id) in books:  # cast to str if keys in JSON are strings
        raise HTTPException(status_code=400, detail='This book is already added.')
    books[str(book.id)] = book.model_dump()

    save_books(books)
    return f'{book.title} by {book.author} added successfully.'

# UPDATE A BOOK

@app.put('/update_book/{book_id}',)
def update_book(book_id: str, book_update: UpdateBook, books=Depends(load_books),user=Depends(get_current_user)):
    if book_id not in books:
        raise HTTPException(status_code=404, detail='Book not found.')

    current_info = books[book_id]
    updates = book_update.model_dump(exclude_unset=True)

    for key, value in updates.items():
        current_info[key] = value

    # validate and rebuild with Book model
    updated_book = Book(**current_info)

    # save as dict (important!)
    books[book_id] = updated_book.model_dump()

    save_books(books)
    return {"message": "Book updated successfully", "book": books[book_id]}

# DELETE A BOOK
@app.delete('/delete_book/{book_id}',)
def delete_book(book_id: str,books=Depends(load_books),user=Depends(get_current_user)):
    if book_id not in books:
        raise HTTPException(status_code=404, detail='Book not found.')
    result = f'{books[book_id]["title"]} by {books[book_id]["author"]} deleted successfully.'
    del books[book_id]

    save_books(books)
    return result

@app.get('/frontend')
def frontend():
    return FileResponse('index.html')

