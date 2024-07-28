import sys
sys.path.append('..')

from starlette.responses import RedirectResponse
from starlette import status
from fastapi import APIRouter, Depends, HTTPException, Request, Form
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from typing import Optional
from pydantic import BaseModel
import models
from .auth import verify_password, get_password_hash, get_current_user
from sqlalchemy.orm import Session
from database import SessionLocal, engine

templates = Jinja2Templates(directory='templates')
models.Base.metadata.create_all(bind=engine)

router = APIRouter(
    prefix='/users',
    tags=['users'],
    responses={404: {'description': 'Not found'}}
)

class UserVerification(BaseModel):
    username: str
    password: str
    new_password: str

def get_db():
   db = SessionLocal()
   try:
       yield db
   finally:
       db.close()

@router.get('/edit-password', response_class=HTMLResponse)
async def edit_user_view(request: Request):
    user = await get_current_user(request)
    if user is None:
        return RedirectResponse('/auth', status_code=status.HTTP_302_FOUND)
    
    return templates.TemplateResponse('edit-user-password.html', {'request': request, 'user': user})

@router.post('/edit-password', response_class=HTMLResponse)
async def user_password_change(request: Request, username: str = Form(...), password: str = Form(...), password2 = Form(...), db: Session = Depends(get_db)):
    user = await get_current_user(request)
    if user is None:
        return RedirectResponse('/auth', status_code=status.HTTP_302_FOUND)
    
    user_data = db.query(models.Users).filter(models.Users.username == username).first()

    msg = 'Invalid username or password'

    if user_data is not None:
        if username == user_data.username and verify_password(password, user_data.hashed_password):
            user_data.hashed_password == get_password_hash(password2)
            db.add(user_data)
            db.commit()

            msg = 'Password updated'

    return templates.TemplateResponse('edit-user-password.html', {'request': request, 'user': user, 'msg': msg})

