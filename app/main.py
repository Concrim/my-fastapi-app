from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, OAuth2PasswordRequestForm
from fastapi.responses import FileResponse
from typing import Optional, Annotated, List
from pydantic import BaseModel, Field, field_validator, model_validator, computed_field
import json
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from app.data import db
import os
from dotenv import load_dotenv
from fastapi import BackgroundTasks
import smtplib
from email.mime.text import MIMEText

# Load env vars
load_dotenv()

################################################ SECURITY ####################################################
SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-key")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

app = FastAPI(
    title="Books API",
    description="Demo API secured with JWT Bearer tokens",
    version="1.0.0"
)

class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    username: str
    fullname: Optional[str] = None
    email: Optional[str] = None
    disabled: Optional[bool] = None

class UserInDB(User):
    hashed_password: str


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
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return {"username": username}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def send_email(to_email: str, subject: str, body: str):
    sender_email = os.getenv("EMAIL_USER")
    sender_password = os.getenv("EMAIL_PASS")

    msg = MIMEText(body, "plain")
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = to_email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, [to_email], msg.as_string())
        print("✅ Email sent successfully")
    except Exception as e:
        print(f"❌ Error sending email: {e}")


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

################################################ MODELS ####################################################
class Book(BaseModel):
    id: Annotated[int, Field(..., gt=0, description="id of the book")]
    title: Annotated[str, Field(..., min_length=5, max_length=50, title="Title",
                                description="The title of the book",
                                examples=["Atomic Habits", "The Messenger Bird"])]
    author: Annotated[str, Field(..., description="Author of the book")]
    year: Annotated[int, Field(..., gt=1950, strict=True, description="Year of release")]
    genre: Optional[List[str]] = None
    rating: Optional[float] = None

    @field_validator("title")
    @classmethod
    def transform_title(cls, value):
        return value.upper()

    @field_validator("rating", mode="after")
    @classmethod
    def validate_rating(cls, value):
        if value is None:
            return value
        if 0 < value <= 5:
            return value
        raise HTTPException(status_code=400, detail="Rating must be between 0 and 5")

    @model_validator(mode="after")
    def check_rating(cls, model):
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
        return "This book is an antique." if self.age > 25 else "Not an antique."

class UpdateBook(BaseModel):
    genre: Optional[List[str]] = None
    rating: Optional[Annotated[float, Field(gt=0, le=5)]] = None


################################################ HELPERS ####################################################
def load_books():
    with open("app/books.json") as f:
        return json.load(f)

def save_books(data):
    with open("app/books.json", "w") as f:
        json.dump(data, f)


################################################ ROUTES ####################################################
@app.get('/')
def home():
    return {'message': 'Hello World'}

@app.get('/books')
def get_books(page_num: int=1, page_size: int=5,books=Depends(load_books)):

    books = list(books.values())
    # using pagination
    start = (page_num - 1) * page_size
    end = start + page_size
    size = len(books)

    response = {
        "books": books[start:end],
        "total": size,
        "page": page_num,
        "pagination": {}
    }

    if end >= size:
        response["pagination"]["next"] = None
        if page_num > 1:
            response["pagination"]["previous"] = f'books?page_num={page_num-1}&page_size={page_size}'
        else:
            response["pagination"]["previous"] = None
    else:
        if page_num > 1:
            response["pagination"]["previous"] = f'books?page_num={page_num-1}&page_size={page_size}'
        else:
            response["pagination"]["previous"] = None

        response['pagination']['next'] = f'books?page_num={page_num+1}&page_size={page_size}'

    return response

@app.get('/books/{book_id}')
def get_book(book_id: str, books=Depends(load_books), user=Depends(get_current_user)):
    if book_id not in books:
        raise HTTPException(status_code=404, detail='Book not found.')
    book = books[book_id]
    return f'{book["title"]} by {book["author"]}'

@app.post('/add_book')
def add_book(
    book: Book,
    background_tasks: BackgroundTasks,
    books=Depends(load_books),
    user=Depends(get_current_user)
):
    if str(book.id) in books:
        raise HTTPException(status_code=400, detail='This book is already added.')

    books[str(book.id)] = book.model_dump()
    save_books(books)

    # Add background task
    background_tasks.add_task(
        send_email,
        os.getenv("ADMIN_EMAIL", "your_email@example.com"),
        "New Book Added 📚",
        f"A new book '{book.title}' by {book.author} was just added."
    )

    return f'{book.title} by {book.author} added successfully. (Email will be sent in background)'


@app.put('/update_book/{book_id}')
def update_book(book_id: str, book_update: UpdateBook, books=Depends(load_books), user=Depends(get_current_user)):
    if book_id not in books:
        raise HTTPException(status_code=404, detail='Book not found.')

    current_info = books[book_id]
    updates = book_update.model_dump(exclude_unset=True)
    current_info.update(updates)

    updated_book = Book(**current_info)
    books[book_id] = updated_book.model_dump()
    save_books(books)
    return {"message": "Book updated successfully", "book": books[book_id]}

@app.delete('/delete_book/{book_id}')
def delete_book(book_id: str, books=Depends(load_books), user=Depends(get_current_user)):
    if book_id not in books:
        raise HTTPException(status_code=404, detail='Book not found.')
    result = f'{books[book_id]["title"]} by {books[book_id]["author"]} deleted successfully.'
    del books[book_id]
    save_books(books)
    return result

@app.get('/frontend')
def frontend():
    return FileResponse('index.html')
