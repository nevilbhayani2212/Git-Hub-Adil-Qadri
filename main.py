from datetime import datetime
import random
from urllib.parse import urlencode, urlparse, urlunparse
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
import smtplib
import jwt
from fastapi.staticfiles import StaticFiles
from requests import Session
from sqlalchemy import asc, cast, desc, func
import uvicorn
from helper.otp import generate_otp
from models import * 
from fastapi import FastAPI, HTTPException, File, Form, Depends, Header, Query, Request, UploadFile
from typing import List, Optional
import razorpay
from fastapi.middleware.cors import CORSMiddleware

import base64
from pathlib import Path
import hashlib

razorpay_client = razorpay.Client(auth=("rzp_test_H953djhP2bC9c5", "OkObIansJTqK69riXRitLRRk"))

SECRET_KEY = "abcd123456987"  
def encode_order_id(order_id: int) -> str:
    """Generate a secure hash for the order ID"""
    data = f"{order_id}-{SECRET_KEY}"
    return hashlib.sha256(data.encode()).hexdigest()[:16]

def decode_and_validate_order_id(encoded_id: str, order_id: int) -> bool:
    """Validate if the encoded ID matches the order ID"""
    expected_hash = encode_order_id(order_id)
    return encoded_id == expected_hash

def send_invoice_email(to_email: str, invoice_html: str):
    """Send invoice email to customer"""
    subject = "Your Order Invoice"
    
    msg = MIMEMultipart()
    msg["From"] = SMTP_EMAIL
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(invoice_html, "html"))  # Using HTML content type

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_EMAIL, SMTP_PASSWORD)
        server.sendmail(SMTP_EMAIL, to_email, msg.as_string())
        server.quit()
    except Exception as e:
        print(f"Failed to send email: {str(e)}")
        raise HTTPException(status_code=400, detail="Failed to send invoice email")





# -----------

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"

SMTP_EMAIL = "nevilbhayani7017@gmail.com"
SMTP_PASSWORD = "rbee qaox gtzw wpwk"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

app = FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8001",  
        "http://localhost:8000",  
        "https://military-daisy-nutten-cart.trycloudflare.com",  # Your Cloudflare tunnel URL
        "https://democracy-clicks-motivated-worry.trycloudflare.com",
        "https://completely-shoot-appreciated-far.trycloudflare.com",
        "https://sep-buttons-photography-anger.trycloudflare.com",
        "*"  # During development only, remove in production
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# EMAIL AUTHENTICATION

def send_email(to_email: str, otp: str):
    subject = "Your OTP Code"
    body = f"Your OTP code is: {otp}"

    msg = MIMEMultipart()
    msg["From"] = SMTP_EMAIL
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_EMAIL, SMTP_PASSWORD)
        server.sendmail(SMTP_EMAIL, to_email, msg.as_string())
        server.quit()

    except Exception as e:
        print(f"Failed to send email: {str(e)}")
        raise HTTPException(status_code=400, detail="Failed to send OTP email")



class User(BaseModel):
    id: int

def generate_jwt(user: User) -> str:
    expiry_time = datetime.datetime.utcnow() + datetime.timedelta(days=1000)
    payload = {
        "exp": expiry_time.timestamp(),
        "id": user.id
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token

def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return {"id": payload.get("id")}
    
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=400, detail="Invalid token")





def generate_invoice_html(order: Order, order_items: list[OrderItem], address: Address) -> str:
    # Load and encode the logo
    logo_path = Path("logo/logo.jpg")
    if logo_path.exists():
        logo_data = base64.b64encode(logo_path.read_bytes()).decode("utf-8")
        logo_html = f'''
        <div style="
            display: inline-block;
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
            border-radius: 8px;
            padding: 4px;
            background: white;
        ">
            <img src="data:image/jpeg;base64,{logo_data}" 
                 alt="Company Logo" 
                 style="max-height: 50px; display: block; border-radius: 4px;">
        </div>
        '''
    
    invoice_date = order.created_at.strftime("%d %b, %Y")
    total_amount = order.total_amount
    
    items_html = ""
    for item in order_items:
        items_html += f"""
        <tr>
            <td>{item.name}</td>
            <td>{item.quantity}</td>
            <td>₹{item.price:.2f}</td>
            <td>₹{item.price * item.quantity:.2f}</td>
        </tr>
        """
    
    invoice_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
            .invoice-box {{ max-width: 800px; margin: auto; padding: 30px; border: 1px solid #eee; }}
            .header {{ display: flex; justify-content: space-between; margin-bottom: 20px; align-items: center; }}
            .address {{ margin-bottom: 20px; }}
            table {{ width: 100%; border-collapse: collapse; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
            .total {{ font-weight: bold; font-size: 1.2em; }}
            .footer {{ margin-top: 30px; text-align: center; font-size: 0.9em; color: #777; }}
            .logo {{ max-height: 80px; }}
        </style>
    </head>
    <body>
        <div class="invoice-box">
            <div class="header">
                <div>
                    <h2>Invoice #{order.id}</h2>
                    <p>Date: {invoice_date}</p>
                </div>
                <div>
                    {logo_html}
                </div>
            </div>
            
            <div class="address">
                <h4>Shipping Address:</h4>
                <p>{address.full_name}</p>
                <p>{address.house_no}, {address.area}</p>
                <p>{address.city}, {address.state} - {address.pincode}</p>
                <p>{address.country}</p>
                <p>Phone: {address.mobile_number}</p>
            </div>
            
            <table>
                <thead>
                    <tr>
                        <th>Product</th>
                        <th>Quantity</th>
                        <th>Unit Price</th>
                        <th>Total</th>
                    </tr>
                </thead>
                <tbody>
                    {items_html}
                </tbody>
                <tfoot>
                    <tr class="total">
                        <td colspan="3">Total Amount</td>
                        <td>₹{total_amount:.2f}</td>
                    </tr>
                </tfoot>
            </table>
            
            <div class="footer">
                <p>Thank you for your order!</p>
            </div>
        </div>
    </body>
    </html>
    """
    return invoice_html






    
@app.get("/")
async def root():
    return {"message": "API is running successfully!"}

@app.post('/api/register')
async def register(
    first_name: str = Form(...),
    last_name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):  
    try:
        if not first_name.strip():
            raise HTTPException(status_code=400, detail="First name is required")
        if not last_name.strip():
            raise HTTPException(status_code=400, detail="Last name is required")
        if not email.strip():
            raise HTTPException(status_code=400, detail="Email is required")
        if not password.strip():
            raise HTTPException(status_code=400, detail="Password is required")

        existing_user = db.query(Register).filter(Register.email == email).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered")
        db_register = Register(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=password,
            is_admin=False
        )
        db.add(db_register)
        db.commit()
        token = generate_jwt(User(id=db_register.id))
        return {
            'status':True,
            "message": "Registration successful",
            "user_id": db_register.id,
            "token": token,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")



@app.post('/api/login')
async def login(
    email: str = Form(...),
    password: str = Form(...), 
    db: Session = Depends(get_db)
):
    try:
        user = db.query(Register).filter(Register.email == email).first()

        if not user:
            raise HTTPException(status_code=400, detail="Invalid email")

        if user.password != password:
            raise HTTPException(status_code=400, detail="Invalid password")

        token = generate_jwt(User(id=user.id))

        return {
            'status':True,
            "message": "Login successful",
            "token": token,
            "user_id": user.id,
            "is_admin": user.is_admin 
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")




@app.post('/api/forgot-password')
async def forgot_password(
    email: str = Form(...),
    db: Session = Depends(get_db)
):
    try:
        user = db.query(Register).filter(Register.email == email).first()

        if not user:
            raise HTTPException(status_code=400, detail="Email not found")

        # otp = generate_otp()
        otp = '000000'
        user.otp = otp
        db.commit()

        send_email(email, otp)

        return {'status':True,"message": "OTP has been sent to your email",}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")



@app.post('/api/verify-otp')
async def verify_otp(
    email: str = Form(...),
    otp: str = Form(...),
    db: Session = Depends(get_db)
):
    try:
        user = db.query(Register).filter(Register.email == email).first()

        if not user:
            raise HTTPException(status_code=400, detail="Invalid email")

        if user.otp != otp:
            raise HTTPException(status_code=400, detail="Invalid OTP")

        token = generate_jwt(User(id=user.id))

        return {
            'status':True,
            "message": "OTP verified successfully",
            "token": token,
            "user_id": user.id,
            "is_admin": user.is_admin 
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")
 


@app.post('/api/new-password')
async def set_new_password(
    request: Request,
    new_password: str = Form(...),
    db: Session = Depends(get_db)
):
    try:
        authorization = request.headers.get("Authorization")
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=400, detail="Authorization header missing or invalid")

        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        print('decoded_token',decoded_token)
        user_id = decoded_token.get("id")
        print('user_id',user_id)

        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid token or user ID not found")

        user = db.query(Register).filter(Register.id == user_id).first()

        if not user:
            raise HTTPException(status_code=400, detail="User not found")

        user.password = new_password  
        db.commit()

        return {
            'status':True,
            "message": "Password updated successfully"
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")




#PRODUCT CRUDE OPERTION


UPLOAD_FOLDER = "uploads/"
# UPLOAD_FOLDER = "uploads/product"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.mount("/uploads", StaticFiles(directory=UPLOAD_FOLDER), name="uploads")


def save_uploaded_files(files: Optional[List[UploadFile]]) -> List[str]:
    paths = []

    if files:
        for file in files:
            path = os.path.join(UPLOAD_FOLDER, file.filename)
            with open(path, "wb") as buffer:
                buffer.write(file.file.read())
            paths.append(path)
    return paths



@app.post('/api/add-categories')
async def add_categories(
    name: str = Form(...),
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")

        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid or expired token")


        user = db.query(Register).filter(Register.id == user_id).first()

        if not user.is_admin:
            raise HTTPException(status_code=400, detail="Only admins can add categories.")

        category = db.query(Category).filter(Category.name == name).first()
        if category:
            raise HTTPException(status_code=400, detail="Category already exists")

        category = Category(name=name)
        db.add(category)
        db.commit()
        db.refresh(category)

        return {
            'status':True,
            "message": "Category added successfully",
            "category_id": category.id
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")



@app.get('/api/get-categories')
async def get_categories(
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")

        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid or expired token")

        user = db.query(Register).filter(Register.id == user_id).first()



        categories = db.query(Category).all()

        return {
            'status':True,
            "categories": [
                {
                    "id": cat.id,
                    "name": cat.name
                }
                for cat in categories
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")



@app.put('/api/update-category/{category_id}')
async def update_category(
    category_id: int,
    name: str = Form(...),
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")

        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid or expired token")

        user = db.query(Register).filter(Register.id == user_id).first()

        if not user.is_admin:
            raise HTTPException(status_code=400, detail="Unauthorized! Only admins can update categories.")

        category = db.query(Category).filter(Category.id == category_id).first()
        if not category:
            raise HTTPException(status_code=400, detail="Category not found")

        category.name = name
        db.commit()
        db.refresh(category)

        return {
            'status':True,
            "message": "Category updated successfully",
            "category_id": category.id
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")



@app.delete('/api/delete-category/{category_id}')
async def delete_category(
    category_id: int,
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")

        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid or expired token")

        user = db.query(Register).filter(Register.id == user_id).first()

        if not user.is_admin:
            raise HTTPException(status_code=400, detail="Unauthorized! Only admins can delete categories.")

        category = db.query(Category).filter(Category.id == category_id).first()
        if not category:
            raise HTTPException(status_code=400, detail="Category not found")

        db.delete(category)
        db.commit()

        return {'status':True,"message": "Category deleted successfully"}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")



# add product
@app.post('/api/add-products')
async def add_products( 
    product_name: str = Form(...),
    product_details: List[str] = Form(...),
    product_price: str = Form(...), 
    product_old_price: str = Form(None),
    images: Optional[List[UploadFile]] = File(None),
    category_id: int = Form(...),
    discount_percentage: str = File(None),
    availability: bool = Form(...),  
    fragrance: Optional[str] = Form(None),
    gender: Optional[str] = Form(None),
    notes: Optional[str] = Form(None),
    sales_count: int = Form(0),
    total_quantity: int = Form(...),
    new_arrival: Optional[bool] = Form(None),
    is_trending: Optional[bool] = Form(None),
    is_sale: Optional[bool] = Form(None),


    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:    
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")

        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid or expired token")

        user = db.query(Register).filter(Register.id == user_id).first()
        if not user.is_admin:
            raise HTTPException(status_code=400, detail="Unauthorized! Only admins can add products.")

        if not product_name.strip():
            raise HTTPException(status_code=400, detail="Product name is required.")

        if not product_price.strip():
            raise HTTPException(status_code=400, detail="Product price is required.")

        if not category_id:
            raise HTTPException(status_code=400, detail="Category ID is required.")

        if not images or len(images) == 0:
            raise HTTPException(status_code=400, detail="At least one product image is required.")
        
        category = db.query(Category).filter(Category.id == category_id).first()
        if not category:
            raise HTTPException(status_code=400, detail="Invalid category ID")

        image_paths = []
        if images:
            image_paths = save_uploaded_files(images)

        created_at = datetime.datetime.utcnow()

        details = " ".join(product_details) if product_details else ""

        product = Products(
            product_name=product_name,
            product_details=details,
            product_price=product_price,
            product_old_price=product_old_price,    
            image=",".join(image_paths) if image_paths else None,
            category_id=int(category_id),
            discount_percentage=discount_percentage,
            availability=availability,
            fragrance=fragrance,
            gender=gender,
            notes=notes,
            sales_count=sales_count,
            created_at=created_at,
            total_quantity=total_quantity,
            new_arrival=new_arrival,
            is_trending=is_trending,
            is_sale=is_sale,
        )

        db.add(product)
        db.commit()
        db.refresh(product)

        return {
            'status':True,
            "message": "Product added successfully",
            "product": {
                "id": product.id,
                "name": product.product_name,
                "category_id": product.category_id,
                "created_at": product.created_at
            }
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")

    

   


# with pagination
# @app.get('/get-products')
# async def get_products(
#     request: Request,
#     category_id: Optional[int] = Query(None),
#     page: int = Query(1, ge=1),
#     page_size: int = Query(28, ge=1),
#     db: Session = Depends(get_db)
# ):
#     try:
#         skip = (page - 1) * page_size
#         query = db.query(Products)

#         if category_id:
#             query = query.filter(Products.category_id == category_id)

#         total_products = query.count()
#         products = query.offset(skip).limit(page_size).all()
        
#         def build_url(new_page: int) -> Optional[str]:
#             if new_page < 1 or new_page > (total_products + page_size - 1) // page_size:
#                 return None
#             query_params = dict(request.query_params)
#             query_params["page"] = str(new_page)
#             url_parts = list(urlparse(str(request.url)))
#             url_parts[4] = urlencode(query_params)
#             return urlunparse(url_parts)

#         formatted_products = []
#         for product in products:
#             product_price = int(product.product_price)
#             product_old_price = int(product.product_old_price)
            
#             # Calculate discount percentage (if old price exists and is greater than current price)
#             if product_old_price > 0 and product_old_price > product_price:
#                 discount_percentage = round(((product_old_price - product_price) / product_old_price) * 100)
#                 rupees_saved = product_old_price - product_price
#             else:
#                 discount_percentage = 0
#                 rupees_saved = 0
                
#             formatted_products.append({
#                 "id": product.id,
#                 "product_name": product.product_name,
#                 "product_details": product.product_details,
#                 "product_price": product_price,
#                 "product_old_price": product_old_price,
#                 "image": product.image if isinstance(product.image, list) else [img.strip() for img in product.image.split(",")],
#                 "category_id": product.category_id,
#                 "category_name": product.category.name if product.category else None,
#                 "discount_percentage": discount_percentage,  
#                 "rupees_saved": rupees_saved,  
#                 "availability": product.availability,
#                 "sales_count": product.sales_count,
#                 "total_quantity": product.total_quantity,
#                 "created_at": product.created_at,
#             })
            
#         return {
#             "count": total_products,
#             "next": build_url(page + 1),
#             "previous": build_url(page - 1),
#             "results": formatted_products
#         }
#     except Exception as e:
#         raise HTTPException(status_code=400, detail=f"Error: {str(e)}")
    





@app.get('/api/get-products')
async def get_products(
    request: Request,
    category_id: Optional[int] = Query(None),
    sort_by: Optional[str] = Query(None, description="Sorting method"),  
    page: int = Query(1, ge=1),
    page_size: int = Query(28, ge=1),
    db: Session = Depends(get_db)
):
    try:
        skip = (page - 1) * page_size
        query = db.query(Products)

        if category_id:
            query = query.filter(Products.category_id == category_id)

        sorting_options = {
            "featured": Products.id,
            "best_selling": Products.sales_count.desc(),
            "alphabetically_a_z": Products.product_name.asc(),
            "alphabetically_z_a": Products.product_name.desc(),
            "price_low_high": asc(cast(Products.product_price, Float)),
            "price_high_low": desc(cast(Products.product_price, Float)),
            "date_old_new": Products.created_at.asc(),
            "date_new_old": Products.created_at.desc(),
        }

        if sort_by:
            if sort_by not in sorting_options:
                raise HTTPException(status_code=400, detail="Invalid sorting option")
            query = query.order_by(sorting_options[sort_by])
        else:
            query = query.order_by(Products.created_at.desc())

        total_products = query.count()
        products = query.offset(skip).limit(page_size).all()
        
        def build_url(new_page: int) -> Optional[str]:
            if new_page < 1 or new_page > (total_products + page_size - 1) // page_size:
                return None
            query_params = dict(request.query_params)
            query_params["page"] = str(new_page)
            url_parts = list(urlparse(str(request.url)))
            url_parts[4] = urlencode(query_params)
            return urlunparse(url_parts)

        formatted_products = []
        for product in products:
            product_price = int(product.product_price)
            product_old_price = int(product.product_old_price or 0)
            
            if product_old_price > 0 and product_old_price > product_price:
                discount_percentage = round(((product_old_price - product_price) / product_old_price) * 100)
                rupees_saved = product_old_price - product_price
            else:
                discount_percentage = 0
                rupees_saved = 0
                
            reviews = db.query(Reviews).filter(Reviews.product_id == product.id).all()
            total_reviews = len(reviews)
            total_stars = sum([review.five_star for review in reviews]) if total_reviews > 0 else 0
            avg_rating = round(total_stars / total_reviews, 1) if total_reviews > 0 else 0.0

            formatted_products.append({
                "id": product.id,
                "product_name": product.product_name,
                "product_details": product.product_details,
                "product_price": product_price,
                "product_old_price": product_old_price,
                "new_arrival":product.new_arrival,
                "is_trending":product.is_trending,
                "is_sale":product.is_sale,
                "image": product.image if isinstance(product.image, list) else [img.strip() for img in product.image.split(",")],
                "category_id": product.category_id,
                "category_name": product.category.name if product.category else None,
                "discount_percentage": discount_percentage,  
                "rupees_saved": rupees_saved,  
                "availability": product.availability,
                "sales_count": product.sales_count,
                # "total_quantity": product.total_quantity,
                "created_at": product.created_at,
                "average_rating": avg_rating,
                "total_reviews": total_reviews,
            })
        return {
            "count": total_products,
            "next": build_url(page + 1),
            "previous": build_url(page - 1),
            "results": formatted_products
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")
    



# @app.get("/get-product-by-id")
# async def get_product_by_id(
#     product_id: int = Form(...),
#     db: Session = Depends(get_db)
# ):
#     try:
#         product = db.query(Products).filter(Products.id == product_id).first()

#         if not product:
#             return {"status": False, "message": "Product not found"}

#         product_data = {
#             "id": product.id,
#             "product_name": product.product_name,
#             "product_details": product.product_details,
#             "product_price": str(product.product_price),
#             "product_old_price": str(product.product_old_price),
#             "image": product.image if isinstance(product.image, list) else [img.strip() for img in product.image.split(",")],
#             "category_id": product.category_id,
#             "category_name": product.category.name if product.category else None,
#             "discount_percentage": int(product.discount_percentage),
#             "availability": product.availability,
#             "fragrance": product.fragrance,
#             "gender": product.gender,
#             "notes": product.notes,
#             "sales_count": product.sales_count,
#             "created_at": product.created_at
#         }

#         return {"status": True, "product": product_data}

#     except Exception as e:
#         raise HTTPException(status_code=400, detail=f"Error: {str(e)}")
    

@app.get("/api/get-product-by-id/")
async def get_product_by_id(
    product_id: int = Query(...),
    db: Session = Depends(get_db)
):
    try:
        product = db.query(Products).filter(Products.id == product_id).first()

        if not product:
            return {"status": False, "message": "Product not found"}

        # Calculate discount and savings
        product_price = int(product.product_price)
        product_old_price = int(product.product_old_price or 0)
        
        if product_old_price > 0 and product_old_price > product_price:
            discount_percentage = round(((product_old_price - product_price) / product_old_price * 100))
            rupees_saved = product_old_price - product_price
        else:
            discount_percentage = 0
            rupees_saved = 0

        reviews = db.query(Reviews).filter(Reviews.product_id == product.id).all()
        total_reviews = len(reviews)
        total_stars = sum([review.five_star for review in reviews]) if total_reviews > 0 else 0
        avg_rating = round(total_stars / total_reviews, 1) if total_reviews > 0 else 0.0
        
        product_data = {
                "id": product.id,
                "product_name": product.product_name,
                "product_details": product.product_details,
                "product_price": product_price,
                "product_old_price": product_old_price,
                "new_arrival":product.new_arrival,
                "is_trending":product.is_trending,
                "is_sale":product.is_sale,
                "image": product.image if isinstance(product.image, list) else [img.strip() for img in product.image.split(",")],
                "category_id": product.category_id,
                "category_name": product.category.name if product.category else None,
                "discount_percentage": discount_percentage,  
                "rupees_saved": rupees_saved,  
                "availability": product.availability,
                "sales_count": product.sales_count,
                "total_quantity": product.total_quantity,
                "created_at": product.created_at,
                "average_rating": avg_rating,
                "total_reviews": total_reviews,
            }
        
        return {"status": True, "product": product_data}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")




@app.put('/api/update-products/{product_id}')
async def update_products(
    product_id: int,
    product_name: Optional[str] = Form(None),
    product_details: Optional[List[str]] = Form(None),
    product_price: Optional[str] = Form(None), 
    product_old_price: Optional[str] = Form(None),
    images: Optional[List[UploadFile]] = File(None),
    category_id: Optional[int] = Form(None),
    discount_percentage: Optional[str] = Form(None),
    availability: Optional[bool] = Form(None), 
    fragrance: Optional[str] = Form(None),
    gender: Optional[str] = Form(None),
    notes: Optional[str] = Form(None),
    sales_count: int = Form(0),
    total_quantity: Optional[int] = Form(None),  
    new_arrival: Optional[bool] = Form(None),
    is_trending: Optional[bool] = Form(None),
    is_sale: Optional[bool] = Form(None),
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")

        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid or expired token")

        user = db.query(Register).filter(Register.id == user_id).first()
        if not user.is_admin:
            raise HTTPException(status_code=400, detail="Unauthorized! Only admins can update products.")

        new_product = db.query(Products).filter(Products.id == product_id).first()
        if not new_product:
            raise HTTPException(status_code=400, detail="Product not found")

        if product_name:
            new_product.product_name = product_name
        if product_details:
            new_product.product_details = ",".join(product_details)
        if product_price:
            new_product.product_price = product_price
        if product_old_price:
            new_product.product_old_price = product_old_price

        if images:
            image_paths = save_uploaded_files(images)
            new_product.image = ",".join(image_paths)
        
        if discount_percentage:
            new_product.discount_percentage = discount_percentage
        if category_id:
            category = db.query(Category).filter(Category.id == category_id).first()
            if not category:
                raise HTTPException(status_code=400, detail="Invalid category_id: category not found")
            new_product.category_id = category_id
        
        if fragrance:
            new_product.fragrance = fragrance
        if gender:
            new_product.gender = gender
        if notes:
            new_product.notes = notes
        if sales_count:
            new_product.sales_count = sales_count

        if total_quantity is not None:
            new_product.total_quantity = total_quantity
            # If availability is not manually set, set based on total_quantity
            if availability is None:
                if total_quantity > 0:
                    new_product.availability = True
                elif total_quantity == 0:
                    new_product.availability = False

        # Manual override of availability
        if availability is not None:
            new_product.availability = availability

        if new_arrival is not None:
            new_product.new_arrival = new_arrival
        if is_trending is not None:
            new_product.is_trending = is_trending
        if is_sale is not None:
            new_product.is_sale = is_sale

        db.commit()
        db.refresh(new_product)

        return {
            'status':True,
            "message": "Product updated successfully",
            "product": {
                "id": new_product.id,
                "product_name": new_product.product_name,
                "product_details": new_product.product_details,
                "product_price": new_product.product_price,
                "product_old_price": new_product.product_old_price,
                "new_arrival": new_product.new_arrival,
                "is_trending": new_product.is_trending,
                "is_sale": new_product.is_sale,
                "image": new_product.image.split(",") if new_product.image else [],
                "discount_percentage": new_product.discount_percentage,
                "fragrance": new_product.fragrance,
                "notes": new_product.notes,
                "created_at": new_product.created_at,
                "categories": new_product.category_id,
                "availability": new_product.availability,
                "gender": new_product.gender,
                "sales_count": new_product.sales_count,
                "total_quantity": new_product.total_quantity,
            },
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")




@app.delete('/api/delete-product/{product_id}')
async def delete_product(
    product_id: int, 
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")

        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid or expired token")

        user = db.query(Register).filter(Register.id == user_id).first()
        if not user.is_admin:
            raise HTTPException(status_code=400, detail="Unauthorized! Only admins can delete products.")

        product = db.query(Products).filter(Products.id == product_id).first()
        if not product:
            raise HTTPException(status_code=400, detail="Product not found")

        db.delete(product)
        db.commit()

        return {
            'status':True,
            "message": "Product deleted successfully",
            "product_id": product_id
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")




# ------------------------- ADD TO CART -------------------------



@app.post('/api/add-to-cart/{product_id}')
async def add_to_cart(
    product_id: int,
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")

        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid or missing token")

        product = db.query(Products).filter(Products.id == product_id).first()
        if not product or not product.availability:
            raise HTTPException(status_code=400, detail=f"Product not Available.")

        product_price = float(product.product_price)
        product_old_price = float(product.product_old_price or 0)
        category_id = product.category_id

        existing_item = db.query(CartItem).filter(
            CartItem.product_id == product_id,
            CartItem.user_id == user_id
        ).first()

        if existing_item:
            existing_item.quantity += 1
            existing_item.price = product_price * existing_item.quantity
            existing_item.old_price = product_old_price * existing_item.quantity
        else:
            existing_item = CartItem(
                user_id=user_id,
                product_id=product.id,
                name=product.product_name,
                category_id=category_id,
                price=product_price,
                old_price=product_old_price,
                quantity=1,
                image=product.image
            )
            db.add(existing_item)

        db.commit()
        db.refresh(existing_item)

        return {
            'status': True,
            "message": "Item added to cart",
            "item": {
                "product_id": existing_item.product_id,
                "name": existing_item.name,
                "price": existing_item.price,
                "old_price": existing_item.old_price,
                "quantity": existing_item.quantity,
                "image": existing_item.image
            }
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"An error occurred: {str(e)}")



@app.get('/api/get-cart-item')
async def get_cart_item(
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")

        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid or missing token")

        cart_items = db.query(CartItem).filter(CartItem.user_id == user_id).all()

        total_payable = 0
        cart_data = []

        for item in cart_items:
            price = float(item.price)
            old_price = float(item.old_price)
            total_payable += price * item.quantity
            image_list = [img.strip() for img in item.image.split(",")] if item.image else []

            if old_price > 0 and old_price > price:
                discount_percentage = round(((old_price - price) / old_price) * 100)
                rupees_saved = old_price - price
            else:
                discount_percentage = 0
                rupees_saved = 0

            cart_data.append({
                "product_id": item.product_id,
                "name": item.name,
                "price": price,
                "old_price": old_price,
                "quantity": item.quantity,
                "image": image_list,
                "discount_percentage": discount_percentage,
                "rupees_saved": rupees_saved
            })
        return {'status': True,"cart_items": cart_data,"Total Payable": total_payable}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")






@app.patch('/api/update-cart-item/{product_id}')
async def update_cart_item(
    product_id: int,
    quantity_change: int = Form(...),
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")

        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid or missing token")

        cart_item = db.query(CartItem).filter(
            CartItem.product_id == product_id,
            CartItem.user_id == user_id
        ).first()

        if not cart_item:
            raise HTTPException(status_code=400, detail="Item not found")

        new_quantity = cart_item.quantity + quantity_change

        if new_quantity <= 0:
            db.delete(cart_item)
            db.commit()
            return {"message": "Item removed from cart"}

        cart_item.quantity = new_quantity
        unit_price = float(cart_item.price) / (cart_item.quantity - quantity_change)
        unit_old_price = float(cart_item.old_price) / (cart_item.quantity - quantity_change)

        cart_item.price = unit_price * new_quantity
        cart_item.old_price = unit_old_price * new_quantity

        db.commit()
        db.refresh(cart_item)

        return {"message": "Cart updated successfully", "item": {
            "product_id": cart_item.product_id,
            "name": cart_item.name,
            "price": cart_item.price,
            "old_price": cart_item.old_price,
            "quantity": cart_item.quantity,
            "image": cart_item.image
        }}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"An error occurred: {str(e)}")


@app.delete('/api/remove-cart-item/{product_id}')
async def remove_cart_item(
    product_id: int,
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")

        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid or missing token")

        cart_item = db.query(CartItem).filter(
            CartItem.product_id == product_id,
            CartItem.user_id == user_id
        ).first()

        if not cart_item:
            raise HTTPException(status_code=400, detail=f"Cart item not found")

        db.delete(cart_item)
        db.commit()

        return {"message": f"Remove cart item successfully."}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"An error occurred: {str(e)}")




@app.get('/api/get-cart-summary')
async def get_cart_summary(
    coupon_code: str = Form(None),
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")
        print(user_id)

        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid or missing token")
        
        cart_items = db.query(CartItem).all()

        if not cart_items:
            raise HTTPException(status_code=400, detail="Cart is empty")
        
        total_mrp = 0
        total_payable = 0
        total_quantity = 0
        category_1_total_quantity = 0
        cart_data = []
        extra_discount = 298

        for item in cart_items:
            if item.category_id == 1:
                category_1_total_quantity += item.quantity

        per_unit_discount = (extra_discount / category_1_total_quantity) if category_1_total_quantity >= 3 else 0


        for item in cart_items:
            item_price = float(item.price)

            item_name = item.name
            item_price = float(item.price) / item.quantity
            item_old_price = float(item.old_price) / item.quantity
            item_quantity = item.quantity

            if item.category_id == 1 and category_1_total_quantity >= 3:
                item_discount = round(per_unit_discount * item.quantity, 2)
                item_price -= item_discount / item.quantity          

            total_mrp += float(item.old_price)
            total_payable += float(item.price)
            total_discount = total_mrp - total_payable
            total_quantity += item_quantity
            
            cart_data.append({
                "name": item_name,
                "price": f"₹{item_price:.2f}",
                "old_price": f"₹{item_old_price:.2f}",
                "quantity": item_quantity,
            })
        
        offer_discount = 0

        if category_1_total_quantity >= 3:
            offer_discount = 298
            total_payable -= offer_discount
        
        elif coupon_code:
            offer = db.query(Offer).filter(Offer.coupon_code == coupon_code).first()

            if offer:
                if total_quantity >= offer.min_products:
                    offer_discount = (offer.discount / 100) * total_payable 
                    total_payable -= offer_discount
                else:
                    return {"message": "Offer not valid due to minimum product requirement"}
        
        order_summary = {
            "Cart Items": cart_data,
            "MRP Total": f"₹{total_mrp}",
            "Discount on MRP": f"₹{total_discount}",
            "Subtotal": f"₹{total_mrp - total_discount}",
            "Total Discount": f"- ₹{offer_discount:.2f}",
            "To Pay": f"₹{total_payable:.2f}"
        }

        return order_summary
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")
    

@app.post('/api/add-offers')
async def add_offers(
    coupon_code: str = Form(...),
    discount: float = Form(...),
    min_products: int = Form(...),
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        admin_id = decoded_token.get("id")
        role = decoded_token.get("role")
        print(admin_id)

        if role != "admin" or not admin_id:
            raise HTTPException(status_code=400, detail="Unauthorized! Only admins can add products.")

        if not admin_id:
            raise HTTPException(status_code=400, detail="Invalid or expired token")
        

        code = db.query(Offer).filter(Offer.coupon_code == coupon_code).first

        if coupon_code == code:
            raise HTTPException(status_code=400, detail="coupon code already use")
        
        db_offer = Offer(
            coupon_code=coupon_code,
            discount=discount,
            min_products=min_products
        )
        db.add(db_offer)
        db.commit()
        db.refresh(db_offer)

        return {"massage": "offer added"}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")
    

@app.get('/api/get-offers')
async def get_offers(
    db:Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")
        print(user_id)

        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid or missing token")
        

        offers = db.query(Offer).all()

        if not offers:
            raise HTTPException(status_code=400, detail="No offers available")
        
        cart_items = db.query(CartItem).all()
        
        if not cart_items:
            raise HTTPException(status_code=400, detail="Cart is empty")
        
        total_quantity = 0
        total_payable = 0

        for item in cart_items:
            total_quantity += item.quantity
            total_payable += float(item.price)
        
        applicable_offers = [
            {
                "coupon_code": offer.coupon_code,
                "savings": f"You Save ₹{(offer.discount / 100) * total_payable:.2f}",
                "description": f"{offer.discount}% Flat Discount On Minimum Purchase Of {offer.min_products} Products"
            }
            for offer in offers if total_quantity >= offer.min_products
        ]

        if not applicable_offers:
            return {"message": "No applicable offers based on your cart quantity"}

        return {"Available Offers": applicable_offers}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")





# Reels Section 


UPLOAD_DIRECTORY = "uploads/videos"
os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)


@app.post('/api/add-videos/{product_id}')
async def add_videos(
    product_id: int,
    upload_video: Optional[List[UploadFile]] = File(None),
    description: str = Form(...),
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        admin_id = decoded_token.get("id")
        role = decoded_token.get("role")
        print(admin_id)

        if role != "admin" or not admin_id:
            raise HTTPException(status_code=400, detail="Unauthorized! Only admins can add videos.")

        admin = db.query(Register).filter(Register.id == admin_id, Register.is_admin == True).first()
        if not admin:
            raise HTTPException(status_code=400, detail="Admin not found or unauthorized")


        product = db.query(Products).filter(Products.id == product_id).first()
        if not product:
            raise HTTPException(status_code=400, detail="Product not found")

        video_paths = []
        if upload_video:
            for video in upload_video:
                video_path = os.path.join(UPLOAD_DIRECTORY, video.filename)
                with open(video_path, "wb") as buffer:
                    buffer.write(await video.read())
                video_paths.append(video_path)


        videos_details = Videos(
            upload_video=",".join(video_paths),
            image=product.image,
            product_name=product.product_name,
            price=product.product_price,
            old_price=product.product_old_price,
            description = description,
        )
        db.add(videos_details)
        db.commit()
        db.refresh(videos_details)

        return videos_details

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error {str(e)}")


@app.put('/api/update-video/{video_id}')
async def update_video(
    video_id: int,
    upload_video: Optional[List[UploadFile]] = File(None),
    description: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        admin_id = decoded_token.get("id")
        role = decoded_token.get("role")
        print(admin_id)

        if role != "admin" or not admin_id:
            raise HTTPException(status_code=400, detail="Unauthorized! Only admins can add videos.")

        admin = db.query(Register).filter(Register.id == admin_id, Register.is_admin == True).first()
        if not admin:
            raise HTTPException(status_code=400, detail="Admin not found or unauthorized")


        video_record = db.query(Videos).filter(Videos.id == video_id).first()
        if not video_record:
            raise HTTPException(status_code=400, detail="Video not found")

        if description:
            video_record.description = description

        if upload_video:
            old_videos = video_record.upload_video.split(',')
            for old_video in old_videos:
                if os.path.exists(old_video):
                    os.remove(old_video)

            new_video_paths = []
            for video in upload_video:
                video_path = os.path.join(UPLOAD_DIRECTORY, video.filename)
                with open(video_path, "wb") as buffer:
                    buffer.write(await video.read())
                new_video_paths.append(video_path)

            video_record.upload_video = ",".join(new_video_paths)

        db.commit()
        db.refresh(video_record)

        return {"message": "Video updated successfully", "video": video_record}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error {str(e)}")



@app.delete('/api/delete-video/{video_id}')
async def delete_video(
    video_id: int, 
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        admin_id = decoded_token.get("id")
        role = decoded_token.get("role")
        print(admin_id)

        if role != "admin" or not admin_id:
            raise HTTPException(status_code=400, detail="Unauthorized! Only admins can add videos.")

        admin = db.query(Register).filter(Register.id == admin_id, Register.is_admin == True).first()
        if not admin:
            raise HTTPException(status_code=400, detail="Admin not found or unauthorized")


        video_record = db.query(Videos).filter(Videos.id == video_id).first()
        if not video_record:
            raise HTTPException(status_code=400, detail="Video not found")

        video_paths = video_record.upload_video.split(',')
        for video_path in video_paths:
            if os.path.exists(video_path):
                os.remove(video_path)

        db.delete(video_record)
        db.commit()

        return {"message": "Video deleted successfully"}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error {str(e)}")
    



@app.get('/api/filter-products/{category_id}')
async def filter_products(
    category_id: int,
    availability: Optional[str] = Form(None),
    min_price: Optional[str] = Form(None),
    max_price: Optional[str] = Form(None),
    fragrance: Optional[str] = Form(None),
    gender: Optional[str] = Form(None),
    notes: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    try:
        total_available = db.query(Products).filter(
            Products.category_id == category_id,
            Products.availability == True
        ).count()
        
        total_unavailable = db.query(Products).filter(
            Products.category_id == category_id,
            Products.availability == False
        ).count()

        filters = [Products.category_id == category_id]
        
        if min_price not in (None, ""): 
            filters.append(cast(Products.product_price, Float) >= float(min_price))
        
        if max_price not in (None, ""):
            filters.append(cast(Products.product_price, Float) <= float(max_price))
        
        if fragrance:
            filters.append(Products.fragrance.like(fragrance))
        
        if gender:
            filters.append(Products.gender.like(gender))
        
        if notes:
            filters.append(Products.notes.like(notes))

        
        filtered_query = db.query(Products).filter(*filters)
        
        
        total_available = filtered_query.filter(Products.availability == True).count()
        total_unavailable = filtered_query.filter(Products.availability == False).count()

        if availability not in (None, ""):
            if availability.lower() in ("true", "1", "yes"): 
                filtered_query = filtered_query.filter(Products.availability == True)
            elif availability.lower() in ("false", "0", "no"):
                filtered_query = filtered_query.filter(Products.availability == False)
            else:
                raise HTTPException(status_code=400, detail="Invalid availability format")
            
        products = filtered_query.all()

        return {
            'status':True,
            "total_available": total_available,
            "total_unavailable": total_unavailable,
            "products": products
        }
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Database error: {str(e)}")


#Search Produts

 
@app.get('/api/search-products/')
async def search_products(
    search_product: str = Query(...),
    db: Session = Depends(get_db)
):
    try:
        search_lower = f"%{search_product.lower()}%"


        search_products = db.query(Products).filter(
            (Products.product_name.ilike(search_lower)) |
            (Products.fragrance.ilike(search_lower)) |
            (Products.gender.ilike(search_lower)) |
            (Products.notes.ilike(search_lower))
        ).all()

        if not search_products:
            return {"message": "No products found matching the search term."}

        return {'status':True,"message": "Products found", "Products": search_products}
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")
    
    

#Product sort_by


@app.get('/api/sort-by/{category_id}')
async def sort_by(
    category_id: int,
    sort_by: Optional[str] = Form(None, description="Sorting method"),
    db: Session = Depends(get_db)
):
    try:
        products = db.query(Products).filter(Products.category_id == category_id)

        if not products.first():
            raise HTTPException(status_code=400, detail="No products found in this category")

        
        sorting_options = {
            "featured": Products.id,
            "best_selling": Products.sales_count.desc(),
            "alphabetically_a_z": Products.product_name.asc(),
            "alphabetically_z_a": Products.product_name.desc(),
            "price_low_high": asc(cast(Products.product_price, Float)),
            "price_high_low": desc(cast(Products.product_price, Float)),
            "date_old_new": Products.created_at.asc(),
            "date_new_old": Products.created_at.desc(),
        }   

        if sort_by not in sorting_options:
            raise HTTPException(status_code=400, detail="Invalid sorting option")

        sorting_products = products.order_by(sorting_options[sort_by]).all()

        return sorting_products

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Internal Server Error: {str(e)}")



#Reviews


UPLOAD_FOLDER2 = "uploads/reviews"


    
@app.post('/api/add-reviews/{product_id}')
async def add_reviews(
    product_id: int,
    five_star: int = Form(...),  
    note: Optional[str] = Form(None),
    title: Optional[str] = Form(None),
    photos_videos: Optional[List[UploadFile]] = File(None),
    db: Session = Depends(get_db),
    authorization: str = Header(...),
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")

        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid or missing token")

        product = db.query(Products).filter(Products.id == product_id).first()
        if not product:
            raise HTTPException(status_code=400, detail="Product not found")

        if five_star < 1 or five_star > 5:
            raise HTTPException(status_code=400, detail="Rating must be between 1 and 5")

        photos_videos_path = []
        if photos_videos:
            for image in photos_videos:
                if image.filename:
                    os.makedirs(UPLOAD_FOLDER2, exist_ok=True)
                    file_path = os.path.join(UPLOAD_FOLDER2, image.filename)
                    with open(file_path, "wb") as buffer:
                        buffer.write(await image.read())
                    photos_videos_path.append(file_path)

        photos_videos_str = ",".join(photos_videos_path) if photos_videos_path else None

        db_reviews = Reviews(
            product_id=product.id,
            user_id=user_id,
            five_star=five_star,
            note=note,
            title=title,
            photos_videos=photos_videos_str,
            review_date=datetime.datetime.utcnow()
        )
        db.add(db_reviews)
        db.commit()
        db.refresh(db_reviews)

        return {
            'status': True,
            "message": "Successfully added review",
            "review": {
                "id": db_reviews.id,
                "product_id": db_reviews.product_id,
                "five_star": db_reviews.five_star,
                "note": db_reviews.note,
                "title": db_reviews.title,
                "photos_videos": db_reviews.photos_videos.split(',') if db_reviews.photos_videos else [],
                "review_date": db_reviews.review_date,
            }
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")
    

    

# @app.get('/get-reviews/{product_id}')
# async def get_reviews(
#     product_id: int,
#     db:Session = Depends(get_db)
# ):
#     try:
#         product = db.query(Products).filter(Products.id == product_id).first()
#         if not product:
#             raise HTTPException(status_code=400, detail="Product not found")

#         reviews = db.query(Reviews).filter(Reviews.product_id == product_id).all()

#         if not reviews:
#             raise HTTPException(status_code=400, detail="No reviews found")
        

#         total_reviews = len(reviews)
#         total_rating = sum(review.five_star for review in reviews)
#         average_rating = round(total_rating / total_reviews, 1) if total_reviews > 0 else 0

    
#         rating_counts = {5: 0, 4: 0, 3: 0, 2: 0, 1: 0}
#         for review in reviews:
#             rating_counts[review.five_star] += 1
        

#         formatted_reviews = []
#         for review in reviews:
#             user = review.user 
#             full_name = f"{user.first_name} {user.last_name}" 
#             formatted_reviews.append({
#                 "name": full_name,
#                 "rating": review.five_star,
#                 "review_date": review.review_date.strftime("%m-%d-%Y"),
#                 "image_videos": review.photos_videos.split(",") if review.photos_videos else []
#             })


#         return {
#             'status': True,
#             "average_rating": average_rating,
#             "total_reviews": total_reviews,
#             "rating_distribution": rating_counts,
#             "reviews": formatted_reviews
#         }

#     except Exception as e:
#         raise HTTPException(status_code=400, detail=f"Error: {str(e)}")



@app.get('/api/get-reviews/{product_id}')
async def get_reviews(
    product_id: int,
    filter: str = Query("newest", description="Sort reviews by: newest (default), highest, lowest"),
    db: Session = Depends(get_db)
):
    try:
        product = db.query(Products).filter(Products.id == product_id).first()
        if not product:
            raise HTTPException(status_code=400, detail="Product not found")

        query = db.query(Reviews).filter(Reviews.product_id == product_id)

        filter = filter.lower()
        if filter == "highest":
            query = query.order_by(desc(Reviews.five_star))
        elif filter == "lowest":
            query = query.order_by(asc(Reviews.five_star))
        elif filter == "newest":
            query = query.order_by(desc(Reviews.review_date))
        else:
            raise HTTPException(status_code=400,detail="Invalid filter. Use: newest, highest, lowest")

        reviews = query.all()

        if not reviews:
            return {
                'status': True,
                'message': "No reviews found",
                'average_rating': 0,
                'total_reviews': 0,
                'rating_distribution': {5: 0, 4: 0, 3: 0, 2: 0, 1: 0},
                'reviews': [],
                'applied_filter': filter
            }

        total_reviews = len(reviews)
        total_rating = sum(review.five_star for review in reviews)
        average_rating = round(total_rating / total_reviews, 1) if total_reviews > 0 else 0

        rating_counts = {5: 0, 4: 0, 3: 0, 2: 0, 1: 0}
        for review in reviews:
            rating_counts[review.five_star] += 1

        formatted_reviews = []
        for review in reviews:
            user = review.user 
            full_name = f"{user.first_name} {user.last_name}" if user else "Anonymous"
            
            formatted_reviews.append({
                "id": review.id,
                "user_id": review.user_id,
                "name": full_name,
                "rating": review.five_star,
                "title": review.title,
                "note": review.note,
                "review_date": review.review_date.strftime("%m-%d-%Y"),
                "photos_videos": review.photos_videos.split(",") if review.photos_videos else []
            })

        return {
            'status': True,
            "average_rating": average_rating,
            "total_reviews": total_reviews,
            "rating_distribution": rating_counts,
            "reviews": formatted_reviews,
            "applied_filter": filter
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Internal server error: {str(e)}")
    



@app.put('/api/edit-reviews/{review_id}')
async def edit_reviews(
    review_id: int,
    five_star: Optional[int] = Form(None),
    note: Optional[str] = Form(None),
    title: Optional[str] = Form(None),
    photos_videos: Optional[List[UploadFile]] = File(None),
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")

        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid or missing token")

        review = db.query(Reviews).filter(Reviews.id == review_id).first()
        if not review:
            raise HTTPException(status_code=400, detail="Review not found")

        if review.user_id != user_id:
            raise HTTPException(status_code=400, detail="You can edit only your own review.")

        if five_star is not None:
            if five_star < 1 or five_star > 5:
                raise HTTPException(status_code=400, detail="Rating must be between 1 and 5")
            review.five_star = five_star

        if note is not None:
            review.note = note

        if title is not None:
            review.title = title

        if photos_videos:
            photos_videos_path = []
            for image in photos_videos:
                if image.filename:
                    os.makedirs(UPLOAD_FOLDER2, exist_ok=True)
                    file_path = os.path.join(UPLOAD_FOLDER2, image.filename)
                    with open(file_path, "wb") as buffer:
                        buffer.write(await image.read())
                    photos_videos_path.append(file_path)
            review.photos_videos = ",".join(photos_videos_path)

        db.commit()
        db.refresh(review)

        return {
            "status": True,
            "message": "Review updated successfully",
            "review": {
                "id": review.id,
                "product_id": review.product_id,
                "five_star": review.five_star,
                "note": review.note,
                "title": review.title,
                "photos_videos": review.photos_videos.split(',') if review.photos_videos else [],
                "review_date": review.review_date,
            }
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")




@app.delete('/api/delete-reviews/{review_id}')
async def delete_reviews(
    review_id: int,
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")

        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid or missing token")

        review = db.query(Reviews).filter(Reviews.id == review_id).first()
        if not review:
            raise HTTPException(status_code=400, detail=f"Review with ID {review_id} not found")
        
        if review.user_id != user_id:
            raise HTTPException(status_code=400, detail="You can delete only your own review.")

        db.delete(review)
        db.commit()
        
        return {'status': True,"message": f"Review deleted successfully."}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")
    


@app.post('/api/store-address')
async def store_address(
    store_name: str = Form(...),
    store_address: str = Form(...),
    state: str = Form(...),
    city: str = Form(...),
    pincode: str = Form(...),
    store_maps: str = Form(...), 
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        admin_id = decoded_token.get("id")
        role = decoded_token.get("role")
        print(admin_id)

        if role != "admin" or not admin_id:
            raise HTTPException(status_code=400, detail="Unauthorized! Only admin can add store address")
        
        admin = db.query(Register).filter(Register.id == admin_id, Register.is_admin == True).first()

        if not admin:
            raise HTTPException(status_code=400, detail="Admin not found or unauthorized")

        db_store = StoreAddress(
        store_name=store_name, 
        store_address=store_address,
        state = state,
        city = city,
        pincode =pincode,
        store_maps=store_maps
        )
        
        db.add(db_store)
        db.commit()
        db.refresh(db_store)
        return {'status':True,"message": "Store added successfully!", "store": db_store}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")
    



@app.delete('/api/delete-store-address/{store_address_id}')
async def delete_store_address(
    store_address_id: int,
    db: Session = Depends(get_db),
    authorization: str = Header(...),
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        admin_id = decoded_token.get("id")
        role = decoded_token.get("role")

        if role != "admin" or not admin_id:
            raise HTTPException(status_code=400, detail="Unauthorized! Only admin can delete store address")
        
        admin = db.query(Register).filter(Register.id == admin_id, Register.is_admin == True).first()

        if not admin:
            raise HTTPException(status_code=400, detail="Admin not found or unauthorized")
        


        store_address = db.query(StoreAddress).filter(StoreAddress.id == store_address_id).first()

        if not store_address:
            raise HTTPException(status_code=400, detail=f"Address with id {store_address_id} not found")

        db.delete(store_address)
        db.commit()

        return {"message": f"Store address with id {store_address_id} deleted successfully"}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")
    



@app.get('/api/get-store-address')
async def get_store_address(
    select_state: str = Form(None),
    select_city: str = Form(None),
    db: Session = Depends(get_db)
):
    try:
        query = db.query(StoreAddress)

        if select_state and select_state.lower() != "all":
            query = query.filter(StoreAddress.state.ilike(f"%{select_state}%"))
        
        if select_city and select_city.lower() != "all":
            query = query.filter(StoreAddress.city.ilike(f"%{select_city}%"))


        store_addresses = query.all()

        if not store_address:
            return {"massage": "No Addresses Found"}
        
        store_list = [
            {
                "store_name": store.store_name,
                "store_address": f"{store.store_address}, {store.city}, {store.state} {store.pincode}",
                "store_maps": store.store_maps
            }
            for store in store_addresses
        ]
        
        return {"message": "Store Addresses Found", "stores": store_list}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")
    



# -------------------- contact-us --------------------

@app.get('/api/get-contact-us')
async def get_contact_us(
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")

        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid or missing token")

        user = db.query(Register).filter(Register.id == user_id).first()

        if not user.is_admin:
            raise HTTPException(status_code=400, detail="Only admins can add categories.")

        contacts = db.query(ContactUs).order_by(ContactUs.id.desc()).all()

        contact_list = []
        for contact in contacts:
            contact_list.append({
                "id": contact.id,
                "name": contact.name,
                "email": contact.email,
                "mobile_number": contact.mobile_number,
                "massage": contact.massage,
            })

        return {"contacts": contact_list}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")
    


@app.post('/api/contact-us')
async def contact_us(
    name: str = Form(...),
    email: str = Form(...),
    mobile_number: str = Form(...),
    massage: str = Form(...),
    db: Session = Depends(get_db),
):
    try:

        contact_us = ContactUs(
            name = name,
            email = email,
            mobile_number = mobile_number,
            massage = massage,
        )

        db.add(contact_us)
        db.commit()
        db.refresh(contact_us)

        return {"message": "Contact added successfully!", "Contact": {
            "id": contact_us.id,
            "name": contact_us.name,
            "email": contact_us.email,
            "mobile_number": contact_us.mobile_number,
            "massage": contact_us.massage,
        }}


    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")
    


@app.delete('/api/delete-contact/{contact_id}')
async def delete_contact(
    contact_id: int,
    db: Session = Depends(get_db)   
):
    try:
        contact_us_id = db.query(ContactUs).filter(ContactUs.id == contact_id).first()
        if not contact_us_id:
            raise HTTPException(status_code=400, detail=f"Contact details not found.")

        db.delete(contact_us_id)
        db.commit()

        return {"message": f"Contact us with id {contact_id} deleted successfully"}
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")
    

# -------------------- Address --------------------
@app.post("/api/add-address")
async def add_address(
    full_name: str = Form(...),
    mobile_number: str = Form(...),
    house_no: str = Form(...),
    area: str = Form(...),
    city: str = Form(...),
    pincode: str = Form(...),
    state: str = Form(...),
    country: str = Form(...),
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        user_id = decode_token(token).get("id")

        new_address = Address(
            user_id=user_id,
            full_name=full_name,
            mobile_number=mobile_number,
            house_no=house_no,
            area=area,
            city=city,
            pincode=pincode,
            state=state,
            country=country
        )

        db.add(new_address)
        db.commit()
        db.refresh(new_address)

        return {"status": True, "message": "Address added successfully", "address_id": new_address.id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/addresses")
async def get_my_addresses(
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        user_id = decode_token(token).get("id")

        addresses = db.query(Address).filter(Address.user_id == user_id).all()

        return {
            "status": True,
            "addresses": [
                {
                    "id": addr.id,
                    "full_name": addr.full_name,
                    "mobile_number": addr.mobile_number,
                    "house_no": addr.house_no,
                    "area": addr.area,
                    "city": addr.city,
                    "pincode": addr.pincode,
                    "state": addr.state,
                    "country": addr.country
                }
                for addr in addresses
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.put("/api/update-address/{address_id}")
async def update_address(
    address_id: int,
    full_name: str = Form(...),
    mobile_number: str = Form(...),
    house_no: str = Form(...),
    area: str = Form(...),
    city: str = Form(...),
    pincode: str = Form(...),
    state: str = Form(...),
    country: str = Form(...),
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        user_id = decode_token(token).get("id")

        address = db.query(Address).filter_by(id=address_id, user_id=user_id).first()
        if not address:
            raise HTTPException(status_code=400, detail="Address not found")

        address.full_name = full_name
        address.mobile_number = mobile_number
        address.house_no = house_no
        address.area = area
        address.city = city
        address.pincode = pincode
        address.state = state
        address.country = country

        db.commit()

        return {"status": True, "message": "Address updated successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))



@app.delete("/api/delete-address/{address_id}")
async def delete_address(
    address_id: int,
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        user_id = decode_token(token).get("id")

        address = db.query(Address).filter_by(id=address_id, user_id=user_id).first()
        if not address:
            raise HTTPException(status_code=400, detail="Address not found")

        db.delete(address)
        db.commit()

        return {"status": True, "message": "Address deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))




# -------- R & D --------
    

# @app.post('/api/checkout')
# async def checkout(
#     address_id: int = Form(...),
#     db: Session = Depends(get_db),
#     authorization: str = Header(...)
# ):
#     try:
#         token = authorization.replace("Bearer ", "")
#         decoded_token = decode_token(token)
#         user_id = decoded_token.get("id")

#         if not user_id:
#             raise HTTPException(status_code=400, detail="Invalid or missing token")

#         address = db.query(Address).filter(
#             Address.id == address_id,
#             Address.user_id == user_id
#         ).first()

#         if not address:
#             raise HTTPException(status_code=400, detail="Address not found or does not belong to the user")

#         cart_items = db.query(CartItem).filter(CartItem.user_id == user_id).all()
#         if not cart_items:
#             raise HTTPException(status_code=400, detail="Your cart is empty")

#         total_amount = sum(float(item.price) for item in cart_items)

#         new_order = Order(
#             user_id=user_id,
#             address_id=address_id,
#             total_amount=total_amount,
#             status=OrderStatus.PENDING.value
#         )
#         db.add(new_order)
#         db.flush()

#         for cart_item in cart_items:
#             order_item = OrderItem(
#                 order_id=new_order.id,
#                 product_id=cart_item.product_id,
#                 name=cart_item.name,
#                 price=float(cart_item.price),
#                 old_price=float(cart_item.old_price),
#                 quantity=cart_item.quantity,
#                 image=cart_item.image
#             )
#             db.add(order_item)

#         user_email = db.query(Register).filter(Register.id == user_id).first().email

#         payment_link = razorpay_client.payment_link.create({
#             "amount": int(total_amount * 100),
#             "currency": "INR",
#             "description": "Order payment for your cart items",
#             "customer": {
#                 "name": address.full_name,
#                 "email": user_email,
#                 "contact": address.mobile_number
#             },
#             "notify": {
#                 "sms": True,
#                 "email": True
#             },
#             "notes": {
#                 "order_id": str(new_order.id),
#                 "token": token
#             },
#             "callback_url": f"https://compatible-loving-treasures-listed.trycloudflare.com/api/verify-payment-callback?order_id={new_order.id}",
#             "callback_method": "get"
#         })

#         new_order.razorpay_order_id = payment_link['id']
#         new_order.payment_link = payment_link['short_url']
#         db.commit()

#         return {
#             "status": True,
#             "message": "Order placed successfully. Please complete payment.",
#             "order_id": new_order.id,
#             "payment_status": "pending",
#             "payment_link": payment_link['short_url']
#         }

#     except Exception as e:
#         raise HTTPException(status_code=400, detail=f"An error occurred: {str(e)}")



@app.post('/api/checkout')
async def checkout(
    address_id: int = Form(...),
    coupon_id: int = Form(None),  
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")

        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid or missing token")

        address = db.query(Address).filter(
            Address.id == address_id,
            Address.user_id == user_id
        ).first()
        if not address:
            raise HTTPException(status_code=400, detail="Address not found or does not belong to the user")

        cart_items = db.query(CartItem).filter(CartItem.user_id == user_id).all()
        if not cart_items:
            raise HTTPException(status_code=400, detail="Your cart is empty")

        total_amount = sum(float(item.price) * item.quantity for item in cart_items)
        discount_amount = 0
        applied_coupon_id = None

        if coupon_id:
            coupon = db.query(Coupon).filter(
                Coupon.id == coupon_id,  
                Coupon.is_active == True
            ).first()
            
            if not coupon:
                raise HTTPException(status_code=400, detail="Invalid coupon ID")
            
            if coupon.min_order_amount and total_amount < coupon.min_order_amount:
                raise HTTPException(status_code=400,detail=f"Minimum order amount of {coupon.min_order_amount} required for this coupon")
            
            existing_usage = db.query(CouponUsage).filter(
                CouponUsage.coupon_id == coupon.id,
                CouponUsage.user_id == user_id
            ).first()
            
            if existing_usage:
                raise HTTPException(status_code=400,detail="You have already used this coupon")
            
            discount_amount = coupon.discount_amount
            total_amount = max(0, total_amount - discount_amount)
            applied_coupon_id = coupon.id

        new_order = Order(
            user_id=user_id,
            address_id=address_id,
            total_amount=total_amount,
            status=OrderStatus.PENDING.value,
            coupon_id=applied_coupon_id
        )
        db.add(new_order)
        db.flush()

        for cart_item in cart_items:
            order_item = OrderItem(
                order_id=new_order.id,
                product_id=cart_item.product_id,
                name=cart_item.name,
                price=float(cart_item.price),
                old_price=float(cart_item.old_price),
                quantity=cart_item.quantity,
                image=cart_item.image
            )
            db.add(order_item)

        user = db.query(Register).filter(Register.id == user_id).first()
        user_email = user.email

        payment_link = razorpay_client.payment_link.create({
            "amount": int(total_amount * 100),
            "currency": "INR",
            "description": "Order payment for your cart items",
            "customer": {
                "name": address.full_name,
                "email": user_email,
                "contact": address.mobile_number
            },
            "notify": {
                "sms": True,
                "email": True
            },
            "notes": {
                "order_id": str(new_order.id),
                "token": token,
                "coupon_id": str(coupon_id) if coupon_id else ""
            },
            "callback_url": f"https://glen-adverse-checkout-gp.trycloudflare.com/api/verify-payment-callback?order_id={new_order.id}",
            "callback_method": "get"
        })

        new_order.razorpay_order_id = payment_link['id']
        new_order.payment_link = payment_link['short_url']
        db.commit()

        return {
            "status": True,
            "message": "Order placed successfully. Please complete payment.",
            "order_id": new_order.id,
            "payment_status": "pending",
            "payment_link": payment_link['short_url'],
            "discount_applied": discount_amount,
            "final_amount": total_amount
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"An error occurred: {str(e)}")
    



@app.get('/api/verify-payment-callback')
async def verify_payment_callback(
    request: Request,
    db: Session = Depends(get_db)
):
    try:
        order_id = int(request.query_params.get("order_id"))
        order = db.query(Order).filter(Order.id == order_id).first()

        if not order:
            raise HTTPException(status_code=400, detail="Order not found")

        payment_link = razorpay_client.payment_link.fetch(order.razorpay_order_id)

        if payment_link['status'] != 'paid':
            raise HTTPException(status_code=400, detail="Payment not completed yet")

        order.status = OrderStatus.PAID.value
        order.razorpay_signature = "Payment completed."

        if order.coupon_id:
            coupon_usage = CouponUsage(
                coupon_id=order.coupon_id,
                user_id=order.user_id,
                order_id=order.id
            )
            db.add(coupon_usage)

        db.query(CartItem).filter(CartItem.user_id == order.user_id).delete()

        order_items = db.query(OrderItem).filter(OrderItem.order_id == order.id).all()
        for item in order_items:
            product = db.query(Products).filter(Products.id == item.product_id).first()
            # if product:
            #     product.sales_count += item.quantity

            #     if product.total_quantity >= item.quantity:
            #         product.total_quantity -= item.quantity
            #     else:
            #         product.total_quantity = 0  

            #     if product.total_quantity == 0:
            #         product.availability = False
            if product:
                product.sales_count += item.quantity
                product.total_quantity = max(0, product.total_quantity - item.quantity)
                if product.total_quantity == 0:
                    product.availability = False


        address = db.query(Address).filter(Address.id == order.address_id).first()
        invoice_html = generate_invoice_html(order, order_items, address)

        # Get user email
        user = db.query(Register).filter(Register.id == order.user_id).first()
        if user and user.email:
            try:
                # Send invoice email
                send_invoice_email(user.email, invoice_html)
            except Exception as email_error:
                # Log email error but don't fail the whole process
                print(f"Failed to send invoice email: {str(email_error)}")

        db.commit()

        return JSONResponse({
            "status": True,
            "message": "Payment verified and order completed",
            "order_id": order.id,
            "coupon_applied": order.coupon_id is not None
        })
    except Exception as e:
        return JSONResponse({"status": False,"message": f"Callback verification failed: {str(e)}"}, status_code=400)


# @app.get('/api/order-history')
# async def get_order_history(
#     db: Session = Depends(get_db),
#     authorization: str = Header(...)
# ):
#     try:
#         token = authorization.replace("Bearer ", "")
#         decoded_token = decode_token(token)
#         user_id = decoded_token.get("id")

#         if not user_id:
#             raise HTTPException(status_code=400, detail="Invalid or missing token")

#         orders = db.query(Order).filter(Order.user_id == user_id,Order.status != OrderStatus.PENDING.value).order_by(Order.created_at.desc()).all()
        
#         order_history = []
#         for order in orders:
#             items = db.query(OrderItem).filter(OrderItem.order_id == order.id).all()
            
#             address = db.query(Address).filter(Address.id == order.address_id).first()
            
#             order_data = {
#                 'order_id': order.id,
#                 'total_amount': order.total_amount,
#                 'status': order.status,
#                 'created_at': order.created_at.strftime('%Y-%m-%d %H:%M:%S') if order.created_at else None,
#                 'address': {
#                     'full_name': address.full_name if address else "",
#                     'mobile_number': address.mobile_number if address else "",
#                     'address': f"{address.house_no}, {address.area}, {address.city}, {address.state}, {address.pincode}" if address else "",
#                 },
#                 'items': [{
#                     'id':item.id,
#                     'name': item.name,
#                     'price': item.price,
#                     'quantity': item.quantity,
#                     'image': item.image.split(',')[0] if item.image else None
#                 } for item in items]
#             }
            
#             order_history.append(order_data)
#         return {'status': True,'orders': order_history}
#     except Exception as e:
#         raise HTTPException(status_code=400, detail=f"An error occurred: {str(e)}")



@app.get('/api/order-history')
async def get_order_history(
    request: Request,  # Add request parameter to access base_url
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")

        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid or missing token")

        orders = db.query(Order).filter(
            Order.user_id == user_id,
            Order.status != OrderStatus.PENDING.value
        ).order_by(Order.created_at.desc()).all()
        
        order_history = []
        for order in orders:
            items = db.query(OrderItem).filter(OrderItem.order_id == order.id).all()
            address = db.query(Address).filter(Address.id == order.address_id).first()
            
            order_hash = encode_order_id(order.id)
            
            # Construct full URL using request.base_url
            base_url = str(request.base_url)
            invoice_url = f"{base_url}api/order/invoice/{order_hash}"
            
            # Alternative if you need to force HTTPS:
            # secure_base_url = str(request.base_url).replace('http://', 'https://')
            # invoice_url = f"{secure_base_url}api/order/invoice/{order_hash}"
            
            order_data = {
                'order_hash': order.id,
                'total_amount': order.total_amount,
                'status': order.status,
                'created_at': order.created_at.strftime('%Y-%m-%d %H:%M:%S') if order.created_at else None,
                'address': {
                    'full_name': address.full_name if address else "",
                    'mobile_number': address.mobile_number if address else "",
                    'address': f"{address.house_no}, {address.area}, {address.city}, {address.state}, {address.pincode}" if address else "",
                },
                'items': [{
                    'id': item.id,
                    'name': item.name,
                    'price': item.price,
                    'quantity': item.quantity,
                    'image': item.image.split(',')[0] if item.image else None
                } for item in items],
                'invoice_url': invoice_url  # Now includes full domain
            }
            
            order_history.append(order_data)
        
        return {'status': True, 'orders': order_history}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"An error occurred: {str(e)}")

    




@app.get('/api/order/')
async def get_order_detail(
    order_id: int = Query(...),
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")
        # is_admin = decoded_token.get("is_admin", False)

        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid or missing token")

        order_query = db.query(Order)
        
        # if not is_admin:
        #     order_query = order_query.filter(Order.user_id == user_id)    
            
        order = order_query.filter(Order.id == order_id).first()
        
        if not order:
            raise HTTPException(status_code=400, detail="Order not found")
            
        items = db.query(OrderItem).filter(OrderItem.order_id == order.id).all()
        
        address = db.query(Address).filter(Address.id == order.address_id).first()
        
        user = db.query(Register).filter(Register.id == order.user_id).first()
        
        order_detail = {
            'order_id': order.id,
            'total_amount': order.total_amount,
            'status': order.status,
            'created_at': order.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': order.updated_at.strftime('%Y-%m-%d %H:%M:%S'),
            'payment_id': order.payment_id,
            'razorpay_order_id': order.razorpay_order_id,
            'user': {
                'id': user.id,
                'name': f"{user.first_name} {user.last_name}",
                'email': user.email
            } if user else None,
            'address': {
                'full_name': address.full_name,
                'mobile_number': address.mobile_number,
                'house_no': address.house_no,
                'area': address.area,
                'city': address.city,
                'state': address.state,
                'pincode': address.pincode,
                'country': address.country
            } if address else None,
            'items': [{
                'id': item.id,
                'product_id': item.product_id,
                'name': item.name,
                'price': item.price,
                'quantity': item.quantity,
                'image': item.image.split(',')[0] if item.image else None,
            } for item in items]
        }
        
        return {
            'status': True,
            'order': order_detail
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"An error occurred: {str(e)}")
    



# Get all orders (admin only)
@app.get('/api/admin-orders')
async def get_all_orders(
    status: str = Query(None),
    db: Session = Depends(get_db),
    authorization: str = Header(...),
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")

        user = db.query(Register).filter(Register.id == user_id).first()
        
        if not user.is_admin:
            raise HTTPException(status_code=400, detail="Admin access required")

        # query = db.query(Order)
        query = db.query(Order).filter(Order.status == OrderStatus.PAID.value)

        if status:
            query = query.filter(Order.status == status)
        else:
            query = query.filter(Order.status != OrderStatus.PENDING.value)
            
        orders = query.order_by(Order.created_at.desc()).all()
        
        order_list = []
        for order in orders:
            user = db.query(Register).filter(Register.id == order.user_id).first()
            
            items = db.query(OrderItem).filter(OrderItem.order_id == order.id).all()
            
            address = db.query(Address).filter(Address.id == order.address_id).first()
            
            order_data = {
                'order_id': order.id,
                'user': {
                    'name': f"{user.first_name} {user.last_name}" if user else "Unknown",
                    'email': user.email if user else None,
                    'id': user.id if user else None
                },
                'total_amount': order.total_amount,
                'status': order.status,
                'created_at': order.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'items': [{
                    'name': item.name,
                    'price': item.price,
                    'quantity': item.quantity,
                    'image': item.image.split(',')[0] if item.image else None,
                    'product_id': item.product_id
                } for item in items],
                'address': {
                    'full_name': address.full_name if address else None,
                    'mobile_number': address.mobile_number if address else None,
                    'complete_address': f"{address.house_no}, {address.area}, {address.city}, {address.state}, {address.country}, {address.pincode}" if address else ""
                } if address else None
            }
            order_list.append(order_data)
        return {
            'status': True,
            'orders': order_list
        }  
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"An error occurred: {str(e)}")
    




# Update order status (admin only)
@app.put('/api/admin-orders-status/{order_id}')
async def update_order_status(
    order_id: int,
    status: str = Form(...),
    db: Session = Depends(get_db),
    authorization: str = Header(...),
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")
        
        user = db.query(Register).filter(Register.id == user_id).first()
        
        if not user.is_admin:
            raise HTTPException(status_code=400, detail="Admin access required")
            
        try:
            new_status = OrderStatus(status).value
        except ValueError:
            valid_statuses = [s.value for s in OrderStatus]
            raise HTTPException(status_code=400, detail=f"Invalid status. Valid statuses are: {', '.join(valid_statuses)}")
            
        order = db.query(Order).filter(Order.id == order_id).first()
        
        if not order:
            raise HTTPException(status_code=400, detail="Order not found")
            
        order.status = new_status
        order.updated_at = datetime.datetime.utcnow()
        db.commit()
        
        return {'status': True,'message': f"Order status updated to {new_status}",'order_id': order.id}
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"An error occurred: {str(e)}")

    

@app.get('/api/admin-dashboard')
async def admin_dashboard(
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")

        if not user_id:
            raise HTTPException(status_code=400, detail="User not found")

        user = db.query(Register).filter(Register.id == user_id).first()

        if not user.is_admin:
            raise HTTPException(status_code=400, detail="Admin access required")

        total_revenue = db.query(func.sum(Order.total_amount)).filter(
            Order.status.in_([OrderStatus.PAID.value, OrderStatus.PROCESSING.value, 
                             OrderStatus.SHIPPED.value, OrderStatus.DELIVERED.value])
        ).scalar()
        
        # status_counts = {}
        # for status in OrderStatus:
        #     count = db.query(Order).filter(Order.status == status.value).count()
        #     status_counts[status.value] = count
            
        status_counts = {}
        for status in OrderStatus:
            if status.value == "pending":
                continue  
            count = db.query(Order).filter(Order.status == status.value).count()
            status_counts[status.value] = count



        total_users = db.query(Register).count()
        
        # top_products = db.query(
        #     Products.id,
        #     Products.product_name,
        #     Products.product_price,
        #     Products.sales_count,
        #     Products.image
        # ).order_by(Products.sales_count.desc()).all()
        
        # top_products_list = [{
        #     'id': product.id,
        #     'name': product.product_name,
        #     'price': int(product.product_price),
        #     'image': product.image.split(',')[0] if product.image else None
        # } for product in top_products]
        
        recent_orders = db.query(Order).order_by(Order.created_at.desc()).limit(6).all()
        total_products = db.query(Products).count()
        
        recent_orders_list = []
        for order in recent_orders:
            user = db.query(Register).filter(Register.id == order.user_id).first()
            
            recent_order = {
                'order_id': order.id,
                'user': f"{user.first_name} {user.last_name}" if user else "Unknown",
                'email': user.email,
                'total_amount': order.total_amount,
                'status': order.status,
                'created_at': order.created_at.strftime('%Y-%m-%d %H:%M:%S')
            }
            recent_orders_list.append(recent_order)
        
        return {
            'status': True,
            'dashboard': {
                'total_revenue': total_revenue,
                'orders_by_status': status_counts,
                'total_users': total_users,
                'total_products': total_products,
                # 'top_selling_products': top_products_list,
                'recent_orders': recent_orders_list
            }}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"An error occurred: {str(e)}")



@app.get('/api/admin-orders-status')
async def get_orders_by_status(
    status: str = Query(None), 
    db: Session = Depends(get_db),
    authorization: str = Header(...),
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")

        user = db.query(Register).filter(Register.id == user_id).first()

        if not user.is_admin:
            raise HTTPException(status_code=400, detail="Admin access required")

        valid_statuses = [OrderStatus.PENDING.value, OrderStatus.PAID.value, 
                          OrderStatus.PROCESSING.value, OrderStatus.SHIPPED.value, 
                          OrderStatus.DELIVERED.value, OrderStatus.CANCELLED.value]

        query = db.query(Order)

        if status:
            if status not in valid_statuses:
                raise HTTPException(status_code=400, detail=f"Invalid status. Valid statuses are: {', '.join(valid_statuses)}")
            query = query.filter(Order.status == status)

        orders = query.order_by(Order.created_at.desc()).all()

        order_list = []
        for order in orders:
            user = db.query(Register).filter(Register.id == order.user_id).first()
            
            items = db.query(OrderItem).filter(OrderItem.order_id == order.id).all()
            
            address = db.query(Address).filter(Address.id == order.address_id).first()
            
            order_data = {
                'order_id': order.id,
                'user': {
                    'name': f"{user.first_name} {user.last_name}" if user else "Unknown",
                    'email': user.email if user else None,
                    'id': user.id if user else None
                },
                'total_amount': order.total_amount,
                'status': order.status,
                'created_at': order.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'items': [{
                    'name': item.name,
                    'price': item.price,
                    'quantity': item.quantity,
                    'image': item.image.split(',')[0] if item.image else None,
                    'product_id': item.product_id
                } for item in items],
                'address': {
                    'full_name': address.full_name if address else None,
                    'mobile_number': address.mobile_number if address else None,
                    'complete_address': f"{address.house_no}, {address.area}, {address.city}, {address.state}, {address.country}, {address.pincode}" if address else ""
                } if address else None
            }
            order_list.append(order_data)
        return {'status': True,'orders': order_list}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"An error occurred: {str(e)}")




# ------------------- Slider -------------------
UPLOAD_DIR = "uploads/slider"
os.makedirs(UPLOAD_DIR, exist_ok=True)


def save_slider_image(file: Optional[UploadFile]) -> Optional[str]:
    if not file:
        return None

    file_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_path, "wb") as buffer:
        buffer.write(file.file.read())
    return file_path



@app.post("/api/slider/add")
async def add_slider_image(
    image: UploadFile = File(...),
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")

        user = db.query(Register).filter(Register.id == user_id).first()
        if not user.is_admin:
            raise HTTPException(status_code=400, detail="Admin access required.")

        image_path = save_slider_image(image)

        slider = Slider(image=image_path, created_at=datetime.datetime.utcnow())
        db.add(slider)
        db.commit()
        db.refresh(slider)

        return {"status": True, "message": "Slider image added", "slider_id": slider.id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")


@app.get("/api/slider/get")
async def get_slider_images(db: Session = Depends(get_db)):
    try:
        sliders = db.query(Slider).order_by(Slider.created_at.desc()).all()
        return {
            "status": True,
            "sliders": [
                {
                    "id": s.id,
                    "image": s.image,
                    "created_at": s.created_at
                }
                for s in sliders
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")


@app.put("/api/slider/update/{slider_id}")
async def update_slider_image(
    slider_id: int,
    image: UploadFile = File(...),
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")

        user = db.query(Register).filter(Register.id == user_id).first()
        if not user or not user.is_admin:
            raise HTTPException(status_code=400, detail="Admin access required")

        slider = db.query(Slider).filter(Slider.id == slider_id).first()
        if not slider:
            raise HTTPException(status_code=400, detail="Slider not found")

        image_path = save_slider_image(image)
        slider.image = image_path
        # slider.created_at = datetime.datetime.utcnow()

        db.commit()
        db.refresh(slider)

        return {"status": True, "message": "Slider updated"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")


@app.delete("/api/slider/delete/{slider_id}")
async def delete_slider_image(
    slider_id: int,
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")

        user = db.query(Register).filter(Register.id == user_id).first()
        if not user or not user.is_admin:
            raise HTTPException(status_code=400, detail="Admin access required")

        slider = db.query(Slider).filter(Slider.id == slider_id).first()
        if not slider:
            raise HTTPException(status_code=400, detail="Slider not found")

        db.delete(slider)
        db.commit()

        return {"status": True, "message": "Slider deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")


@app.get("/api/top-selling-products")
def get_top_selling_products(db: Session = Depends(get_db)):
    try:
        top_products = db.query(Products)\
                         .order_by(Products.sales_count.desc())\
                         .all()

        result = []
        for product in top_products:
            product_price = int(product.product_price)
            product_old_price = int(product.product_old_price or 0)

            if product_old_price > 0 and product_old_price > product_price:
                discount_percentage = round(((product_old_price - product_price) / product_old_price) * 100)
                rupees_saved = product_old_price - product_price
            else:
                discount_percentage = 0
                rupees_saved = 0

            result.append({
                "id": product.id,
                "product_name": product.product_name,
                "product_details": product.product_details or "",
                "new_arrival": product.new_arrival,
                "is_trending": product.is_trending,
                "is_sale": product.is_sale,
                "product_price": product_price,
                "product_old_price": product_old_price,
                "image": product.image if isinstance(product.image, list) else [img.strip() for img in product.image.split(",")],
                "category_id": product.category_id,
                "category_name": product.category.name if product.category else None,
                "discount_percentage": discount_percentage,
                "rupees_saved": rupees_saved,
                "availability": product.availability,
                "sales_count": product.sales_count,
                "total_quantity": product.total_quantity,
                "created_at": product.created_at
            })

        return {
            "status": True,
            "message": "Top selling products",
            "data": result
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error fetching top products: {str(e)}")

    

@app.get("/api/get-discounted-products")
async def get_discounted_products(request: Request, db: Session = Depends(get_db)):
    try:
        query = db.query(Products).all()
        discounted_products = []

        for product in query:
            try:
                product_price = int(product.product_price)
                product_old_price = int(product.product_old_price or 0)
            except:
                continue

            if product_old_price > 0 and product_old_price > product_price:
                discount_percentage = round(((product_old_price - product_price) / product_old_price) * 100)
            else:
                discount_percentage = 0

            if discount_percentage > 30:
                discounted_products.append({
                    "id": product.id,
                    "product_name": product.product_name,
                    "product_details": product.product_details,
                    "new_arrival": product.new_arrival,
                    "is_trending": product.is_trending,
                    "is_sale": product.is_sale,
                    "product_price": product_price,
                    "product_old_price": product_old_price,
                    "discount_percentage": discount_percentage,
                    "image": product.image if isinstance(product.image, list) else [img.strip() for img in product.image.split(",")],
                    "category_id": product.category_id,
                    "category_name": product.category.name if product.category else None,
                    "availability": product.availability,
                    "sales_count": product.sales_count,
                    "total_quantity": product.total_quantity,
                    "created_at": product.created_at,
                })

        return {
            "count": len(discounted_products),
            "results": discounted_products
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")



@app.get("/api/get-trending-new-arrival-products")
async def get_trending_new_arrival_products(request: Request, db: Session = Depends(get_db)):
    try:
        products = db.query(Products).filter((Products.is_trending == True) | (Products.new_arrival == True)).all()

        result = []

        for product in products:
            try:
                product_price = int(product.product_price)
                product_old_price = int(product.product_old_price or 0)
            except:
                continue

            if product_old_price > 0 and product_old_price > product_price:
                discount_percentage = round(((product_old_price - product_price) / product_old_price) * 100)
            else:
                discount_percentage = 0

            result.append({
                "id": product.id,
                "product_name": product.product_name,
                "product_details": product.product_details,
                "product_price": product_price,
                "product_old_price": product_old_price,
                "discount_percentage": discount_percentage,
                "is_trending": product.is_trending,
                "new_arrival": product.new_arrival,
                "is_sale": product.is_sale,
                "image": product.image if isinstance(product.image, list) else [img.strip() for img in product.image.split(",")],
                "category_id": product.category_id,
                "category_name": product.category.name if product.category else None,
                "availability": product.availability,
                "sales_count": product.sales_count,
                "total_quantity": product.total_quantity,
                "created_at": product.created_at,
            })
        return {"count": len(result),"results": result}
    except Exception as e:


        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")

@app.get("/api/get-sale")
async def get_sale_products(request: Request, db: Session = Depends(get_db)):
    try:
        products = db.query(Products).filter((Products.is_sale == True)).all()

        result = []

        for product in products:
            try:
                product_price = int(product.product_price)
                product_old_price = int(product.product_old_price or 0)
            except:
                continue

            if product_old_price > 0 and product_old_price > product_price:
                discount_percentage = round(((product_old_price - product_price) / product_old_price) * 100)
            else:
                discount_percentage = 0

            result.append({
                "id": product.id,
                "product_name": product.product_name,
                "product_details": product.product_details,
                "is_sale": product.is_sale,
                "product_price": product_price,
                "product_old_price": product_old_price,
                "discount_percentage": discount_percentage,
                "is_trending": product.is_trending,
                "new_arrival": product.new_arrival,
                "image": product.image if isinstance(product.image, list) else [img.strip() for img in product.image.split(",")],
                "category_id": product.category_id,
                "category_name": product.category.name if product.category else None,
                "availability": product.availability,
                "sales_count": product.sales_count,
                "total_quantity": product.total_quantity,
                "created_at": product.created_at,
            })
        return {"count": len(result),"results": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")



@app.post('/api/admin/create-coupon')
async def create_coupon(
    code: str = Form(...),
    discount_amount: float = Form(...),
    min_order_amount: float = Form(None),
    is_active: bool = Form(True),
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")
        
        user = db.query(Register).filter(Register.id == user_id).first()
        if not user.is_admin:
            raise HTTPException(status_code=403, detail="Only admin can create coupons")

        existing_coupon = db.query(Coupon).filter(Coupon.code == code).first()
        if existing_coupon:
            raise HTTPException(status_code=400, detail="Coupon code already exists")

        if discount_amount <= 0:
            raise HTTPException(status_code=400, detail="Discount amount must be positive")

        new_coupon = Coupon(
            code=code,
            discount_amount=discount_amount,
            min_order_amount=min_order_amount,
            is_active=is_active
        )
        db.add(new_coupon)
        db.commit()
        db.refresh(new_coupon)

        return {
            'status': True,
            'message': 'Coupon created successfully',
            'coupon': {
                'id': new_coupon.id,
                'code': new_coupon.code,
                'discount_amount': new_coupon.discount_amount,
                'min_order_amount': new_coupon.min_order_amount,
                'is_active': new_coupon.is_active
            }
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"An error occurred: {str(e)}")
    



@app.get('/api/get-available-coupons')
async def get_available_coupons(
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")
        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid or missing token")

        coupons = db.query(Coupon).filter(Coupon.is_active == True).all()

        available_coupons = []
        for coupon in coupons:
            usage = db.query(CouponUsage).filter(
                CouponUsage.coupon_id == coupon.id,
                CouponUsage.user_id == user_id
            ).first()
            
            if not usage:
                available_coupons.append({
                    'id': coupon.id,
                    'code': coupon.code,
                    'discount_amount': coupon.discount_amount,
                    'min_order_amount': coupon.min_order_amount
                })
        return {'status': True,'coupons': available_coupons}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"An error occurred: {str(e)}")
    

@app.put('/api/admin/update-coupon/{coupon_id}')
async def update_coupon(
    coupon_id: int,
    code: str = Form(None),
    discount_amount: float = Form(None),
    min_order_amount: float = Form(None),
    is_active: bool = Form(None),
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")
        
        user = db.query(Register).filter(Register.id == user_id).first()
        if not user.is_admin:
            raise HTTPException(status_code=403, detail="Only admin can update coupons")

        coupon = db.query(Coupon).filter(Coupon.id == coupon_id).first()
        if not coupon:
            raise HTTPException(status_code=404, detail="Coupon not found")

        if code and code != coupon.code:
            existing_coupon = db.query(Coupon).filter(Coupon.code == code).first()
            if existing_coupon:
                raise HTTPException(status_code=400, detail="Coupon code already exists")

        if discount_amount is not None and discount_amount <= 0:
            raise HTTPException(status_code=400, detail="Discount amount must be positive")

        if code is not None:
            coupon.code = code
        if discount_amount is not None:
            coupon.discount_amount = discount_amount
        if min_order_amount is not None:
            coupon.min_order_amount = min_order_amount
        if is_active is not None:
            coupon.is_active = is_active

        coupon.updated_at = datetime.datetime.utcnow()
        db.commit()
        db.refresh(coupon)

        return {
            'status': True,
            'message': 'Coupon updated successfully',
            'coupon': {
                'id': coupon.id,
                'code': coupon.code,
                'discount_amount': coupon.discount_amount,
                'min_order_amount': coupon.min_order_amount,
                'is_active': coupon.is_active,
                'updated_at': coupon.updated_at
            }
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"An error occurred: {str(e)}")
    


@app.delete('/api/admin/delete-coupon/{coupon_id}')
async def delete_coupon(
    coupon_id: int,
    db: Session = Depends(get_db),
    authorization: str = Header(...)
):
    try:
        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")
        
        user = db.query(Register).filter(Register.id == user_id).first()
        if not user.is_admin:
            raise HTTPException(status_code=403, detail="Only admin can delete coupons")

        coupon = db.query(Coupon).filter(Coupon.id == coupon_id).first()
        if not coupon:
            raise HTTPException(status_code=404, detail="Coupon not found")

        usage_count = db.query(CouponUsage).filter(CouponUsage.coupon_id == coupon_id).count()
        if usage_count > 0:
            raise HTTPException(status_code=400,detail="Cannot delete coupon that has been used. Deactivate it instead.")

        db.delete(coupon)
        db.commit()

        return {
            'status': True,
            'message': 'Coupon deleted successfully',
            'deleted_coupon_id': coupon_id
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"An error occurred: {str(e)}")



@app.get('/api/admin/get-all-products/')
async def get_all_products(
    request: Request,
    category_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1),
    authorization: str = Header(...)
):
    try:

        token = authorization.replace("Bearer ", "")
        decoded_token = decode_token(token)
        user_id = decoded_token.get("id")
        
        user = db.query(Register).filter(Register.id == user_id).first()
        if not user.is_admin:
            raise HTTPException(status_code=403, detail="Only admin can delete coupons")
        
        skip = (page - 1) * page_size
        query = db.query(Products)

        if category_id:
            query = query.filter(Products.category_id == category_id)

        query = query.order_by(Products.created_at.desc())

        total_products = query.count()
        products = query.offset(skip).limit(page_size).all()

        def build_url(new_page: int) -> Optional[str]:
            if new_page < 1 or new_page > (total_products + page_size - 1) // page_size:
                return None
            query_params = dict(request.query_params)
            query_params["page"] = str(new_page)
            url_parts = list(urlparse(str(request.url)))
            url_parts[4] = urlencode(query_params)
            return urlunparse(url_parts)

        formatted_products = []
        for product in products:
            product_price = int(product.product_price)
            product_old_price = int(product.product_old_price or 0)

            if product_old_price > 0 and product_old_price > product_price:
                discount_percentage = round(((product_old_price - product_price) / product_old_price) * 100)
                rupees_saved = product_old_price - product_price
            else:
                discount_percentage = 0
                rupees_saved = 0

            reviews = db.query(Reviews).filter(Reviews.product_id == product.id).all()
            total_reviews = len(reviews)
            total_stars = sum([review.five_star for review in reviews]) if total_reviews > 0 else 0
            avg_rating = round(total_stars / total_reviews, 1) if total_reviews > 0 else 0.0

            formatted_products.append({
                "id": product.id,
                "product_name": product.product_name,
                "product_details": product.product_details,
                "product_price": product_price,
                "product_old_price": product_old_price,
                "new_arrival": product.new_arrival,
                "is_trending": product.is_trending,
                "is_sale": product.is_sale,
                "image": product.image if isinstance(product.image, list) else [img.strip() for img in product.image.split(",")],
                "category_id": product.category_id,
                "category_name": product.category.name if product.category else None,
                "discount_percentage": discount_percentage,
                "rupees_saved": rupees_saved,
                "availability": product.availability,
                "sales_count": product.sales_count,
                "total_quantity": product.total_quantity,
                "created_at": product.created_at,
                "average_rating": avg_rating,
                "total_reviews": total_reviews,
            })

        return {
            "count": total_products,
            "next": build_url(page + 1),
            "previous": build_url(page - 1),
            "results": formatted_products
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")



# @app.get('/api/order/invoice/{order_id}', response_class=HTMLResponse)
# async def get_invoice(
#     order_id: int,
#     db: Session = Depends(get_db),
# ):
#     try:
#         order = db.query(Order).filter(Order.id == order_id,).first()
#         if not order:
#             raise HTTPException(status_code=404, detail="Order not found")
#         order_items = db.query(OrderItem).filter(OrderItem.order_id == order.id).all()
#         address = db.query(Address).filter(Address.id == order.address_id).first()
#         invoice_html = generate_invoice_html(order, order_items, address)
        
#         return HTMLResponse(content=invoice_html)
#     except Exception as e:
#         raise HTTPException(status_code=400, detail=str(e))
    

@app.get('/api/order/invoice/{order_hash}', response_class=HTMLResponse)
async def get_invoice(
    order_hash: str,
    db: Session = Depends(get_db)
):
    try:
        # Find all orders that could match this hash
        orders = db.query(Order).all()
        
        # Find the order that matches the hash
        matched_order = None
        for order in orders:
            if decode_and_validate_order_id(order_hash, order.id):
                matched_order = order
                break
        
        if not matched_order:
            raise HTTPException(status_code=404, detail="Order not found")
        
        # Get order details
        order_items = db.query(OrderItem).filter(OrderItem.order_id == matched_order.id).all()
        address = db.query(Address).filter(Address.id == matched_order.address_id).first()
        
        if not address:
            raise HTTPException(status_code=404, detail="Address not found")
            
        invoice_html = generate_invoice_html(matched_order, order_items, address)
        return HTMLResponse(content=invoice_html)
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    

    
if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8001, reload=True)