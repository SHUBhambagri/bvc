from fastapi import FastAPI, APIRouter, HTTPException, Depends, Header, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr, ConfigDict
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt
import razorpay
from emergentintegrations.payments.stripe.checkout import StripeCheckout, CheckoutSessionResponse, CheckoutStatusResponse, CheckoutSessionRequest

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.environ.get("JWT_SECRET", "wallpix-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 10080  # 7 days

security = HTTPBearer()

# Payment Gateways
razorpay_client = razorpay.Client(auth=(os.environ.get('RAZORPAY_KEY_ID', 'test'), os.environ.get('RAZORPAY_KEY_SECRET', 'test')))
stripe_api_key = os.environ.get('STRIPE_API_KEY', 'sk_test_emergent')

# Create the main app
app = FastAPI()
api_router = APIRouter(prefix="/api")

# ===== MODELS =====

class UserRegister(BaseModel):
    email: EmailStr
    password: str
    name: str
    phone: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: str
    name: str
    phone: Optional[str] = None
    addresses: List[Dict[str, Any]] = []
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class Product(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    price: float
    images: List[str]
    category: str
    sizes: List[str]
    stock: int
    featured: bool = False
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class ProductCreate(BaseModel):
    name: str
    description: str
    price: float
    images: List[str]
    category: str
    sizes: List[str]
    stock: int
    featured: bool = False

class CartItem(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    product_id: str
    quantity: int
    size: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class CartItemAdd(BaseModel):
    product_id: str
    quantity: int
    size: str

class WishlistItem(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    product_id: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class Review(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    product_id: str
    user_id: str
    user_name: str
    rating: int
    comment: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class ReviewCreate(BaseModel):
    product_id: str
    rating: int
    comment: str

class Order(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    order_number: str
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    items: List[Dict[str, Any]]
    total: float
    shipping_address: Dict[str, Any]
    payment_method: str
    payment_status: str = "pending"
    shipping_status: str = "pending"
    tracking_id: Optional[str] = None
    coupon_applied: Optional[str] = None
    discount_amount: float = 0.0
    shipping_cost: float = 0.0
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class OrderCreate(BaseModel):
    items: List[Dict[str, Any]]
    shipping_address: Dict[str, Any]
    payment_method: str
    coupon_code: Optional[str] = None

class Coupon(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    code: str
    discount_type: str  # "percentage" or "fixed"
    discount_value: float
    min_order: float = 0.0
    max_uses: Optional[int] = None
    used_count: int = 0
    valid_until: str
    active: bool = True
    influencer_name: Optional[str] = None

class CouponCreate(BaseModel):
    code: str
    discount_type: str
    discount_value: float
    min_order: float = 0.0
    max_uses: Optional[int] = None
    valid_until: str
    influencer_name: Optional[str] = None

class CouponValidate(BaseModel):
    code: str
    order_total: float

class ContactForm(BaseModel):
    name: str
    email: EmailStr
    message: str

class PaymentTransaction(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    order_id: Optional[str] = None
    user_id: Optional[str] = None
    amount: float
    currency: str
    payment_method: str  # "stripe" or "razorpay"
    payment_status: str = "pending"
    metadata: Dict[str, Any] = {}
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

# ===== HELPER FUNCTIONS =====

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = await db.users.find_one({"id": user_id}, {"_id": 0})
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return User(**user)

async def get_current_admin(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        admin_id: str = payload.get("sub")
        role: str = payload.get("role")
        if admin_id is None or role != "admin":
            raise HTTPException(status_code=403, detail="Admin access required")
    except JWTError:
        raise HTTPException(status_code=403, detail="Invalid admin token")
    
    admin = await db.admin_users.find_one({"id": admin_id}, {"_id": 0})
    if admin is None:
        raise HTTPException(status_code=403, detail="Admin not found")
    return admin

# ===== AUTH ROUTES =====

@api_router.post("/auth/register")
async def register(user: UserRegister):
    # Check if user exists
    existing_user = await db.users.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    user_obj = User(
        email=user.email,
        name=user.name,
        phone=user.phone
    )
    user_dict = user_obj.model_dump()
    user_dict["password_hash"] = get_password_hash(user.password)
    
    await db.users.insert_one(user_dict)
    
    # Create token
    access_token = create_access_token(data={"sub": user_obj.id})
    
    return {
        "token": access_token,
        "user": {
            "id": user_obj.id,
            "email": user_obj.email,
            "name": user_obj.name
        }
    }

@api_router.post("/auth/login")
async def login(credentials: UserLogin):
    user = await db.users.find_one({"email": credentials.email})
    if not user or not verify_password(credentials.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    access_token = create_access_token(data={"sub": user["id"]})
    
    return {
        "token": access_token,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "name": user["name"]
        }
    }

@api_router.get("/auth/me")
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user

@api_router.post("/admin/login")
async def admin_login(credentials: UserLogin):
    admin = await db.admin_users.find_one({"email": credentials.email})
    if not admin or not verify_password(credentials.password, admin["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    
    access_token = create_access_token(data={"sub": admin["id"], "role": "admin"})
    
    return {
        "token": access_token,
        "admin": {
            "id": admin["id"],
            "email": admin["email"]
        }
    }

# ===== PRODUCT ROUTES =====

@api_router.get("/products")
async def get_products(
    category: Optional[str] = None,
    size: Optional[str] = None,
    min_price: Optional[float] = None,
    max_price: Optional[float] = None,
    search: Optional[str] = None,
    featured: Optional[bool] = None
):
    query = {}
    
    if category:
        query["category"] = category
    if size:
        query["sizes"] = size
    if min_price or max_price:
        query["price"] = {}
        if min_price:
            query["price"]["$gte"] = min_price
        if max_price:
            query["price"]["$lte"] = max_price
    if search:
        query["$or"] = [
            {"name": {"$regex": search, "$options": "i"}},
            {"description": {"$regex": search, "$options": "i"}}
        ]
    if featured is not None:
        query["featured"] = featured
    
    products = await db.products.find(query, {"_id": 0}).to_list(1000)
    return products

@api_router.get("/products/{product_id}")
async def get_product(product_id: str):
    product = await db.products.find_one({"id": product_id}, {"_id": 0})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return product

@api_router.get("/categories")
async def get_categories():
    # Get unique categories from products
    pipeline = [
        {"$group": {"_id": "$category", "count": {"$sum": 1}}},
        {"$project": {"_id": 0, "name": "$_id", "count": 1}}
    ]
    categories = await db.products.aggregate(pipeline).to_list(100)
    return categories

@api_router.post("/admin/products")
async def create_product(product: ProductCreate, admin = Depends(get_current_admin)):
    product_obj = Product(**product.model_dump())
    product_dict = product_obj.model_dump()
    
    await db.products.insert_one(product_dict)
    return product_obj

@api_router.put("/admin/products/{product_id}")
async def update_product(product_id: str, product: ProductCreate, admin = Depends(get_current_admin)):
    result = await db.products.update_one(
        {"id": product_id},
        {"$set": product.model_dump()}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    
    return {"message": "Product updated successfully"}

@api_router.delete("/admin/products/{product_id}")
async def delete_product(product_id: str, admin = Depends(get_current_admin)):
    result = await db.products.delete_one({"id": product_id})
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    
    return {"message": "Product deleted successfully"}

# ===== CART ROUTES =====

@api_router.get("/cart")
async def get_cart(current_user: User = Depends(get_current_user)):
    cart_items = await db.cart_items.find({"user_id": current_user.id}, {"_id": 0}).to_list(100)
    
    # Populate product details
    for item in cart_items:
        product = await db.products.find_one({"id": item["product_id"]}, {"_id": 0})
        if product:
            item["product"] = product
    
    return cart_items

@api_router.post("/cart/add")
async def add_to_cart(item: CartItemAdd, current_user: User = Depends(get_current_user)):
    # Check if item already exists
    existing_item = await db.cart_items.find_one({
        "user_id": current_user.id,
        "product_id": item.product_id,
        "size": item.size
    })
    
    if existing_item:
        # Update quantity
        await db.cart_items.update_one(
            {"id": existing_item["id"]},
            {"$inc": {"quantity": item.quantity}}
        )
        return {"message": "Cart updated"}
    else:
        # Create new cart item
        cart_item = CartItem(
            user_id=current_user.id,
            product_id=item.product_id,
            quantity=item.quantity,
            size=item.size
        )
        await db.cart_items.insert_one(cart_item.model_dump())
        return {"message": "Added to cart"}

@api_router.delete("/cart/remove/{item_id}")
async def remove_from_cart(item_id: str, current_user: User = Depends(get_current_user)):
    result = await db.cart_items.delete_one({"id": item_id, "user_id": current_user.id})
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Cart item not found")
    
    return {"message": "Removed from cart"}

@api_router.put("/cart/update/{item_id}")
async def update_cart_item(item_id: str, quantity: int, current_user: User = Depends(get_current_user)):
    if quantity <= 0:
        return await remove_from_cart(item_id, current_user)
    
    result = await db.cart_items.update_one(
        {"id": item_id, "user_id": current_user.id},
        {"$set": {"quantity": quantity}}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Cart item not found")
    
    return {"message": "Cart updated"}

# ===== WISHLIST ROUTES =====

@api_router.get("/wishlist")
async def get_wishlist(current_user: User = Depends(get_current_user)):
    wishlist_items = await db.wishlist.find({"user_id": current_user.id}, {"_id": 0}).to_list(100)
    
    # Populate product details
    for item in wishlist_items:
        product = await db.products.find_one({"id": item["product_id"]}, {"_id": 0})
        if product:
            item["product"] = product
    
    return wishlist_items

@api_router.post("/wishlist/add/{product_id}")
async def add_to_wishlist(product_id: str, current_user: User = Depends(get_current_user)):
    # Check if already in wishlist
    existing = await db.wishlist.find_one({
        "user_id": current_user.id,
        "product_id": product_id
    })
    
    if existing:
        return {"message": "Already in wishlist"}
    
    wishlist_item = WishlistItem(
        user_id=current_user.id,
        product_id=product_id
    )
    await db.wishlist.insert_one(wishlist_item.model_dump())
    return {"message": "Added to wishlist"}

@api_router.delete("/wishlist/remove/{product_id}")
async def remove_from_wishlist(product_id: str, current_user: User = Depends(get_current_user)):
    result = await db.wishlist.delete_one({
        "user_id": current_user.id,
        "product_id": product_id
    })
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Wishlist item not found")
    
    return {"message": "Removed from wishlist"}

# ===== REVIEW ROUTES =====

@api_router.get("/reviews/{product_id}")
async def get_reviews(product_id: str):
    reviews = await db.reviews.find({"product_id": product_id}, {"_id": 0}).to_list(100)
    return reviews

@api_router.post("/reviews/create")
async def create_review(review: ReviewCreate, current_user: User = Depends(get_current_user)):
    # Check if user already reviewed this product
    existing = await db.reviews.find_one({
        "user_id": current_user.id,
        "product_id": review.product_id
    })
    
    if existing:
        raise HTTPException(status_code=400, detail="You have already reviewed this product")
    
    review_obj = Review(
        product_id=review.product_id,
        user_id=current_user.id,
        user_name=current_user.name,
        rating=review.rating,
        comment=review.comment
    )
    
    await db.reviews.insert_one(review_obj.model_dump())
    return review_obj

# ===== COUPON ROUTES =====

@api_router.post("/coupons/validate")
async def validate_coupon(coupon_data: CouponValidate):
    coupon = await db.coupons.find_one({"code": coupon_data.code.upper()}, {"_id": 0})
    
    if not coupon:
        raise HTTPException(status_code=404, detail="Invalid coupon code")
    
    if not coupon["active"]:
        raise HTTPException(status_code=400, detail="Coupon is not active")
    
    # Check expiry
    if datetime.fromisoformat(coupon["valid_until"]) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Coupon has expired")
    
    # Check min order
    if coupon_data.order_total < coupon["min_order"]:
        raise HTTPException(status_code=400, detail=f"Minimum order amount is ₹{coupon['min_order']}")
    
    # Check max uses
    if coupon["max_uses"] and coupon["used_count"] >= coupon["max_uses"]:
        raise HTTPException(status_code=400, detail="Coupon usage limit reached")
    
    # Calculate discount
    discount = 0.0
    if coupon["discount_type"] == "percentage":
        discount = (coupon_data.order_total * coupon["discount_value"]) / 100
    else:
        discount = coupon["discount_value"]
    
    return {
        "valid": True,
        "discount": discount,
        "coupon": coupon
    }

@api_router.post("/admin/coupons")
async def create_coupon(coupon: CouponCreate, admin = Depends(get_current_admin)):
    # Check if code already exists
    existing = await db.coupons.find_one({"code": coupon.code.upper()})
    if existing:
        raise HTTPException(status_code=400, detail="Coupon code already exists")
    
    coupon_obj = Coupon(**coupon.model_dump())
    coupon_dict = coupon_obj.model_dump()
    coupon_dict["code"] = coupon_dict["code"].upper()
    
    await db.coupons.insert_one(coupon_dict)
    return coupon_obj

@api_router.get("/admin/coupons")
async def get_all_coupons(admin = Depends(get_current_admin)):
    coupons = await db.coupons.find({}, {"_id": 0}).to_list(100)
    return coupons

# ===== ORDER ROUTES =====

@api_router.post("/orders/create")
async def create_order(order_data: OrderCreate, current_user: Optional[User] = None):
    # For guest checkout, current_user will be None
    try:
        current_user = await get_current_user(security)
    except:
        current_user = None
    
    # Calculate total
    total = sum(item["price"] * item["quantity"] for item in order_data.items)
    
    # Apply coupon if provided
    discount_amount = 0.0
    if order_data.coupon_code:
        coupon_validation = await validate_coupon(CouponValidate(
            code=order_data.coupon_code,
            order_total=total
        ))
        discount_amount = coupon_validation["discount"]
    
    # Calculate shipping (placeholder - will be replaced with Shiprocket)
    shipping_cost = 0.0 if total > 500 else 50.0
    
    final_total = total - discount_amount + shipping_cost
    
    # Create order
    order = Order(
        order_number=f"WP{datetime.now(timezone.utc).strftime('%Y%m%d')}{str(uuid.uuid4())[:6].upper()}",
        user_id=current_user.id if current_user else None,
        user_email=order_data.shipping_address.get("email"),
        items=order_data.items,
        total=final_total,
        shipping_address=order_data.shipping_address,
        payment_method=order_data.payment_method,
        coupon_applied=order_data.coupon_code,
        discount_amount=discount_amount,
        shipping_cost=shipping_cost
    )
    
    await db.orders.insert_one(order.model_dump())
    
    # Update coupon usage
    if order_data.coupon_code:
        await db.coupons.update_one(
            {"code": order_data.coupon_code.upper()},
            {"$inc": {"used_count": 1}}
        )
    
    # Clear cart for logged-in users
    if current_user:
        await db.cart_items.delete_many({"user_id": current_user.id})
    
    return order

@api_router.get("/orders/{order_id}")
async def get_order(order_id: str):
    order = await db.orders.find_one({"id": order_id}, {"_id": 0})
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    return order

@api_router.get("/orders/track/{order_number}")
async def track_order(order_number: str, email: Optional[str] = None):
    query = {"order_number": order_number.upper()}
    if email:
        query["user_email"] = email
    
    order = await db.orders.find_one(query, {"_id": 0})
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    return order

@api_router.get("/orders/my-orders")
async def get_my_orders(current_user: User = Depends(get_current_user)):
    orders = await db.orders.find({"user_id": current_user.id}, {"_id": 0}).sort("created_at", -1).to_list(100)
    return orders

@api_router.get("/admin/orders")
async def get_all_orders(admin = Depends(get_current_admin)):
    orders = await db.orders.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    return orders

@api_router.put("/admin/orders/{order_id}/status")
async def update_order_status(
    order_id: str,
    payment_status: Optional[str] = None,
    shipping_status: Optional[str] = None,
    tracking_id: Optional[str] = None,
    admin = Depends(get_current_admin)
):
    update_data = {}
    if payment_status:
        update_data["payment_status"] = payment_status
    if shipping_status:
        update_data["shipping_status"] = shipping_status
    if tracking_id:
        update_data["tracking_id"] = tracking_id
    
    result = await db.orders.update_one(
        {"id": order_id},
        {"$set": update_data}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Order not found")
    
    return {"message": "Order status updated"}

# ===== PAYMENT ROUTES (STRIPE) =====

@api_router.post("/payments/stripe/create-session")
async def create_stripe_session(request: Request, order_id: str):
    # Get order
    order = await db.orders.find_one({"id": order_id}, {"_id": 0})
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    
    # Get host URL from request
    host_url = str(request.base_url)
    webhook_url = f"{host_url}api/payments/stripe/webhook"
    
    stripe_checkout = StripeCheckout(api_key=stripe_api_key, webhook_url=webhook_url)
    
    # Build success and cancel URLs
    origin = request.headers.get("origin", host_url)
    success_url = f"{origin}/order-success?session_id={{CHECKOUT_SESSION_ID}}"
    cancel_url = f"{origin}/checkout"
    
    # Create checkout session
    checkout_request = CheckoutSessionRequest(
        amount=float(order["total"]),
        currency="usd",
        success_url=success_url,
        cancel_url=cancel_url,
        metadata={
            "order_id": order_id,
            "order_number": order["order_number"]
        }
    )
    
    session = await stripe_checkout.create_checkout_session(checkout_request)
    
    # Create payment transaction record
    transaction = PaymentTransaction(
        session_id=session.session_id,
        order_id=order_id,
        user_id=order.get("user_id"),
        amount=order["total"],
        currency="usd",
        payment_method="stripe",
        payment_status="pending",
        metadata={"order_number": order["order_number"]}
    )
    
    await db.payment_transactions.insert_one(transaction.model_dump())
    
    return {"url": session.url, "session_id": session.session_id}

@api_router.get("/payments/stripe/status/{session_id}")
async def get_stripe_status(session_id: str, request: Request):
    # Get transaction
    transaction = await db.payment_transactions.find_one({"session_id": session_id}, {"_id": 0})
    if not transaction:
        raise HTTPException(status_code=404, detail="Transaction not found")
    
    # If already processed, return status
    if transaction["payment_status"] == "paid":
        return transaction
    
    # Check with Stripe
    host_url = str(request.base_url)
    webhook_url = f"{host_url}api/payments/stripe/webhook"
    stripe_checkout = StripeCheckout(api_key=stripe_api_key, webhook_url=webhook_url)
    
    status = await stripe_checkout.get_checkout_status(session_id)
    
    # Update transaction and order if paid
    if status.payment_status == "paid" and transaction["payment_status"] != "paid":
        await db.payment_transactions.update_one(
            {"session_id": session_id},
            {"$set": {"payment_status": "paid"}}
        )
        
        await db.orders.update_one(
            {"id": transaction["order_id"]},
            {"$set": {"payment_status": "paid"}}
        )
    
    # Get updated transaction
    updated_transaction = await db.payment_transactions.find_one({"session_id": session_id}, {"_id": 0})
    return updated_transaction

@api_router.post("/payments/stripe/webhook")
async def stripe_webhook(request: Request):
    body = await request.body()
    signature = request.headers.get("Stripe-Signature")
    
    host_url = str(request.base_url)
    webhook_url = f"{host_url}api/payments/stripe/webhook"
    stripe_checkout = StripeCheckout(api_key=stripe_api_key, webhook_url=webhook_url)
    
    try:
        webhook_response = await stripe_checkout.handle_webhook(body, signature)
        
        # Update transaction and order
        if webhook_response.payment_status == "paid":
            transaction = await db.payment_transactions.find_one({"session_id": webhook_response.session_id})
            if transaction and transaction["payment_status"] != "paid":
                await db.payment_transactions.update_one(
                    {"session_id": webhook_response.session_id},
                    {"$set": {"payment_status": "paid"}}
                )
                
                await db.orders.update_one(
                    {"id": transaction["order_id"]},
                    {"$set": {"payment_status": "paid"}}
                )
        
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# ===== PAYMENT ROUTES (RAZORPAY) =====

@api_router.post("/payments/razorpay/create-order")
async def create_razorpay_order(order_id: str):
    # Get order
    order = await db.orders.find_one({"id": order_id}, {"_id": 0})
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    
    # Create Razorpay order
    amount_in_paise = int(order["total"] * 100)
    
    razorpay_order = razorpay_client.order.create({
        "amount": amount_in_paise,
        "currency": "INR",
        "payment_capture": 1,
        "receipt": order["order_number"][:40]
    })
    
    # Create payment transaction record
    transaction = PaymentTransaction(
        session_id=razorpay_order["id"],
        order_id=order_id,
        user_id=order.get("user_id"),
        amount=order["total"],
        currency="INR",
        payment_method="razorpay",
        payment_status="pending",
        metadata={"order_number": order["order_number"]}
    )
    
    await db.payment_transactions.insert_one(transaction.model_dump())
    
    return {
        "order_id": razorpay_order["id"],
        "amount": razorpay_order["amount"],
        "currency": razorpay_order["currency"],
        "key_id": os.environ.get('RAZORPAY_KEY_ID', 'test')
    }

@api_router.post("/payments/razorpay/verify")
async def verify_razorpay_payment(
    razorpay_order_id: str,
    razorpay_payment_id: str,
    razorpay_signature: str
):
    # Verify signature
    try:
        razorpay_client.utility.verify_payment_signature({
            'razorpay_order_id': razorpay_order_id,
            'razorpay_payment_id': razorpay_payment_id,
            'razorpay_signature': razorpay_signature
        })
    except:
        raise HTTPException(status_code=400, detail="Invalid payment signature")
    
    # Update transaction and order
    transaction = await db.payment_transactions.find_one({"session_id": razorpay_order_id})
    if transaction and transaction["payment_status"] != "paid":
        await db.payment_transactions.update_one(
            {"session_id": razorpay_order_id},
            {"$set": {"payment_status": "paid"}}
        )
        
        await db.orders.update_one(
            {"id": transaction["order_id"]},
            {"$set": {"payment_status": "paid"}}
        )
    
    return {"status": "success", "message": "Payment verified successfully"}

# ===== CONTACT ROUTE =====

@api_router.post("/contact")
async def submit_contact_form(form: ContactForm):
    # Store contact form submission
    contact_dict = form.model_dump()
    contact_dict["id"] = str(uuid.uuid4())
    contact_dict["created_at"] = datetime.now(timezone.utc).isoformat()
    
    await db.contact_forms.insert_one(contact_dict)
    
    return {"message": "Thank you for contacting us. We'll get back to you soon!"}

# ===== SHIPPING ROUTES (SHIPROCKET STRUCTURE) =====

@api_router.post("/shipping/calculate")
async def calculate_shipping(
    weight: float,
    pickup_pincode: str,
    delivery_pincode: str,
    cod: bool = False
):
    # Placeholder for Shiprocket API integration
    # In production, this will call Shiprocket's rate calculator API
    
    # Mock calculation
    base_cost = 50.0
    if weight > 1.0:
        base_cost += (weight - 1.0) * 20.0
    if cod:
        base_cost += 30.0
    
    return {
        "shipping_cost": base_cost,
        "estimated_days": "3-5 business days",
        "note": "Shiprocket API credentials required for live calculation"
    }

@api_router.post("/shipping/create-order")
async def create_shipping_order(order_id: str, admin = Depends(get_current_admin)):
    # Placeholder for Shiprocket order creation
    # In production, this will call Shiprocket's order creation API
    
    order = await db.orders.find_one({"id": order_id}, {"_id": 0})
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    
    # Mock AWB number
    awb_number = f"AWB{datetime.now(timezone.utc).strftime('%Y%m%d')}{str(uuid.uuid4())[:8].upper()}"
    
    # Update order with tracking ID
    await db.orders.update_one(
        {"id": order_id},
        {"$set": {
            "tracking_id": awb_number,
            "shipping_status": "shipped"
        }}
    )
    
    return {
        "awb_number": awb_number,
        "message": "Shipping order created (Shiprocket API credentials required for live integration)"
    }

@api_router.get("/shipping/track/{awb}")
async def track_shipment(awb: str):
    # Placeholder for Shiprocket tracking API
    # In production, this will call Shiprocket's tracking API
    
    return {
        "awb": awb,
        "status": "In Transit",
        "location": "Mumbai Hub",
        "note": "Shiprocket API credentials required for live tracking"
    }

# ===== ADMIN INITIALIZATION =====

@api_router.post("/admin/init")
async def init_admin():
    # Check if admin exists
    admin = await db.admin_users.find_one({"email": "admin@wallpix.com"})
    if admin:
        return {"message": "Admin already exists"}
    
    # Create default admin
    admin_dict = {
        "id": str(uuid.uuid4()),
        "email": "admin@wallpix.com",
        "password_hash": get_password_hash("admin123"),
        "role": "admin",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.admin_users.insert_one(admin_dict)
    
    return {
        "message": "Admin created successfully",
        "email": "admin@wallpix.com",
        "password": "admin123",
        "note": "Please change this password immediately"
    }

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
