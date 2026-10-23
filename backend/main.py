
import os
from datetime import datetime, timezone
from typing import Optional

import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field

from .database import get_connection
from .security import hash_password, verify_password, create_token

load_dotenv()

app = FastAPI(title="BookWorld API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8081",
        "http://localhost:8081",
        "http://127.0.0.1:5500",
        "http://localhost:5500",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -------------------- REQUEST MODELS --------------------

class RegisterData(BaseModel):
    full_name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class LoginData(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class OrderItemData(BaseModel):
    book_id: int = Field(gt=0)
    quantity: int = Field(gt=0, le=100)


class OrderData(BaseModel):
    items: list[OrderItemData] = Field(min_length=1)
    payment_method: str = Field(min_length=2, max_length=30)
    address: str = Field(min_length=5, max_length=300)


class ReviewData(BaseModel):
    book_id: int = Field(gt=0)
    rating: int = Field(ge=1, le=5)
    review_text: str = Field(min_length=1, max_length=1000)


# -------------------- HELPERS --------------------

def get_current_user_id(authorization: Optional[str]) -> int:
    """Read the logged-in user's ID from the JWT bearer token."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Please log in first.")

    token = authorization.split(" ", 1)[1].strip()
    secret = os.getenv("JWT_SECRET")

    if not secret or secret.lower().startswith("change"):
        raise HTTPException(
            status_code=500,
            detail="Configure JWT_SECRET in your .env file."
        )

    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        user_id = payload.get("sub", payload.get("user_id"))

        if user_id is None:
            raise ValueError("Token has no user ID.")

        return int(user_id)

    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired login token.")


def get_book_details(cursor, book_id: int):
    cursor.execute(
        """
        SELECT book_id, title, price, stock
        FROM BW_BOOKS
        WHERE book_id = :book_id
        FOR UPDATE
        """,
        {"book_id": book_id},
    )
    return cursor.fetchone()


# -------------------- HOME AND DATABASE --------------------

@app.get("/")
def home():
    return {"message": "BookWorld API is running!"}


@app.get("/api/health")
def health():
    try:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT
                        USER,
                        SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA'),
                        SYS_CONTEXT('USERENV', 'DB_NAME'),
                        SYS_CONTEXT('USERENV', 'SERVICE_NAME')
                    FROM DUAL
                """)
                row = cursor.fetchone()

        return {
            "status": "connected",
            "connected_user": row[0],
            "current_schema": row[1],
            "database_name": row[2],
            "service_name": row[3],
        }

    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Oracle connection failed: {exc}")


# -------------------- REGISTRATION --------------------

@app.post("/api/register", status_code=201)
def register(data: RegisterData):
    conn = None

    try:
        conn = get_connection()

        with conn.cursor() as cursor:
            email = str(data.email).strip().lower()

            cursor.execute(
                "SELECT user_id FROM BW_USERS WHERE LOWER(email) = :email",
                {"email": email},
            )

            if cursor.fetchone():
                raise HTTPException(
                    status_code=409,
                    detail="This email is already registered.",
                )

            new_id = cursor.var(int)

            cursor.execute(
                """
                INSERT INTO BW_USERS (full_name, email, password_hash)
                VALUES (:name, :email, :password_hash)
                RETURNING user_id INTO :new_id
                """,
                {
                    "name": data.full_name.strip(),
                    "email": email,
                    "password_hash": hash_password(data.password),
                    "new_id": new_id,
                },
            )

            user_id = int(new_id.getvalue()[0])

        conn.commit()

        return {
            "message": "Registration successful",
            "user_id": user_id,
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise

    except Exception as exc:
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail=f"Registration failed: {exc}")

    finally:
        if conn:
            conn.close()


# -------------------- LOGIN --------------------

@app.post("/api/login")
def login(data: LoginData):
    try:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT user_id, full_name, email, password_hash
                    FROM BW_USERS
                    WHERE LOWER(email) = :email
                    """,
                    {"email": str(data.email).strip().lower()},
                )
                user = cursor.fetchone()

        if not user or not verify_password(data.password, user[3]):
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password.",
            )

        return {
            "message": "Login successful",
            "access_token": create_token(int(user[0])),
            "token_type": "bearer",
            "user": {
                "user_id": int(user[0]),
                "full_name": user[1],
                "email": user[2],
            },
        }

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Login failed: {exc}")


# -------------------- BOOK CATALOGUE --------------------

@app.get("/api/books")
def get_books(
    search: str = Query(default="", max_length=150),
    category_id: Optional[int] = Query(default=None, gt=0),
):
    conn = None

    try:
        conn = get_connection()

        with conn.cursor() as cursor:
            query = """
                SELECT DISTINCT
                    b.book_id,
                    b.title,
                    b.price,
                    b.stock,
                    b.category_id,
                    c.category_name,
                    a.author_name,
                    b.ISBN
                FROM BW_BOOKS b
                LEFT JOIN BW_CATEGORIES c
                    ON b.category_id = c.category_id
                LEFT JOIN BW_BOOK_AUTHORS ba
                    ON b.book_id = ba.book_id
                LEFT JOIN BW_AUTHORS a
                    ON ba.author_id = a.author_id
                WHERE (
                    LOWER(b.title) LIKE :search
                    OR LOWER(a.author_name) LIKE :search
                    OR LOWER(c.category_name) LIKE :search
                )
            """

            params = {"search": f"%{search.strip().lower()}%"}

            if category_id is not None:
                query += " AND b.category_id = :category_id"
                params["category_id"] = category_id

            query += " ORDER BY b.book_id"

            cursor.execute(query, params)

            return [
                {
                    "book_id": row[0],
                    "title": row[1],
                    "price": float(row[2]),
                    "stock": row[3],
                    "category_id": row[4],
                    "category": row[5],
                    "author": row[6],
                    "isbn": row[7],  # Added ISBN
                }
                for row in cursor.fetchall()
            ]

    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Could not load books: {exc}")

    finally:
        if conn:
            conn.close()


@app.get("/api/categories")
def get_categories():
    try:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT category_id, category_name, description
                    FROM BW_CATEGORIES
                    ORDER BY category_name
                """)

                return [
                    {
                        "category_id": row[0],
                        "category_name": row[1],
                        "description": row[2],
                    }
                    for row in cursor.fetchall()
                ]

    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Could not load categories: {exc}")


@app.get("/api/books/{book_id}")
def get_book(book_id: int):
    try:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT
                        b.book_id, b.title, b.price, b.stock,
                        b.category_id, c.category_name, a.author_name
                    FROM BW_BOOKS b
                    LEFT JOIN BW_CATEGORIES c
                        ON b.category_id = c.category_id
                    LEFT JOIN BW_BOOK_AUTHORS ba
                        ON b.book_id = ba.book_id
                    LEFT JOIN BW_AUTHORS a
                        ON ba.author_id = a.author_id
                    WHERE b.book_id = :book_id
                """, {"book_id": book_id})

                rows = cursor.fetchall()

        if not rows:
            raise HTTPException(status_code=404, detail="Book not found.")

        first = rows[0]
        return {
            "book_id": first[0],
            "title": first[1],
            "price": float(first[2]),
            "stock": first[3],
            "category_id": first[4],
            "category": first[5],
            "authors": list(dict.fromkeys(row[6] for row in rows if row[6])),
        }

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Could not load book: {exc}")


# -------------------- CHECKOUT / ORDERS --------------------

@app.post("/api/orders", status_code=201)
def create_order(
    data: OrderData,
    authorization: Optional[str] = Header(default=None),
):
    """
    Creates an order for an authenticated user.
    Prices and stock are read from Oracle, not trusted from the browser.
    """
    user_id = get_current_user_id(authorization)
    conn = None

    allowed_methods = {"UPI", "CARD", "COD"}
    payment_method = data.payment_method.strip().upper()

    if payment_method not in allowed_methods:
        raise HTTPException(
            status_code=422,
            detail="Payment method must be UPI, CARD, or COD.",
        )

    try:
        conn = get_connection()

        with conn.cursor() as cursor:
            # Confirm the user exists.
            cursor.execute(
                "SELECT user_id FROM BW_USERS WHERE user_id = :user_id",
                {"user_id": user_id},
            )
            if not cursor.fetchone():
                raise HTTPException(status_code=401, detail="User account not found.")

            # Combine duplicate book IDs so stock is checked correctly.
            quantities = {}
            for item in data.items:
                quantities[item.book_id] = (
                    quantities.get(item.book_id, 0) + item.quantity
                )

            order_lines = []
            total = 0.0

            for book_id, quantity in quantities.items():
                book = get_book_details(cursor, book_id)

                if not book:
                    raise HTTPException(
                        status_code=404,
                        detail=f"Book ID {book_id} was not found.",
                    )

                title, price, stock = book[1], float(book[2]), int(book[3])

                if quantity > stock:
                    raise HTTPException(
                        status_code=409,
                        detail=f"Not enough stock for '{title}'. Available: {stock}.",
                    )

                line_total = price * quantity
                total += line_total

                order_lines.append({
                    "book_id": book_id,
                    "title": title,
                    "quantity": quantity,
                    "price": price,
                })

            # Assumes BW_ORDERS has ORDER_ID, USER_ID, ORDER_DATE,
            # ORDER_STATUS and TOTAL_AMOUNT.
            new_order_id = cursor.var(int)

            cursor.execute("""
                INSERT INTO BW_ORDERS
                    (user_id, order_date, order_status, total_amount)
                VALUES
                    (:user_id, :order_date, :status, :total)
                RETURNING order_id INTO :new_order_id
            """, {
                "user_id": user_id,
                "order_date": datetime.now(timezone.utc).replace(tzinfo=None),
                "status": "PLACED",
                "total": total,
                "new_order_id": new_order_id,
            })

            order_id = int(new_order_id.getvalue()[0])

            for line in order_lines:
                cursor.execute("""
                    INSERT INTO BW_ORDER_ITEMS
                        (order_id, book_id, quantity, unit_price)
                    VALUES
                        (:order_id, :book_id, :quantity, :price)
                """, {
                    "order_id": order_id,
                    "book_id": line["book_id"],
                    "quantity": line["quantity"],
                    "price": line["price"],
                })

                cursor.execute("""
                    UPDATE BW_BOOKS
                    SET stock = stock - :quantity
                    WHERE book_id = :book_id
                """, {
                    "quantity": line["quantity"],
                    "book_id": line["book_id"],
                })

            # This records the chosen method; no real payment is processed.
            # Assumes BW_PAYMENTS has PAYMENT_METHOD, PAYMENT_STATUS,
            # AMOUNT and ORDER_ID.
            cursor.execute("""
                INSERT INTO BW_PAYMENTS
                    (order_id, payment_method, payment_status, amount)
                VALUES
                    (:order_id, :method, :status, :amount)
            """, {
                "order_id": order_id,
                "method": payment_method,
                "status": "PENDING" if payment_method != "COD" else "PAY_ON_DELIVERY",
                "amount": total,
            })

        conn.commit()

        return {
            "message": "Order placed successfully",
            "order_id": order_id,
            "total": round(total, 2),
            "payment_method": payment_method,
            "payment_status": (
                "PENDING" if payment_method != "COD" else "PAY_ON_DELIVERY"
            ),
            "items": order_lines,
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise

    except Exception as exc:
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail=f"Could not place order: {exc}")

    finally:
        if conn:
            conn.close()


@app.get("/api/orders")
def get_my_orders(authorization: Optional[str] = Header(default=None)):
    user_id = get_current_user_id(authorization)

    try:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT order_id, order_date, order_status, total_amount
                    FROM BW_ORDERS
                    WHERE user_id = :user_id
                    ORDER BY order_date DESC
                """, {"user_id": user_id})

                orders = cursor.fetchall()

        return [
            {
                "order_id": row[0],
                "order_date": row[1].isoformat() if row[1] else None,
                "status": row[2],
                "total": float(row[3]),
            }
            for row in orders
        ]

    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Could not load orders: {exc}")


# -------------------- REVIEWS --------------------

@app.get("/api/books/{book_id}/reviews")
def get_reviews(book_id: int):
    try:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT
                        r.review_id,
                        r.user_id,
                        u.full_name,
                        r.rating,
                        r.review_text,
                        r.created_at
                    FROM BW_REVIEWS r
                    JOIN BW_USERS u ON u.user_id = r.user_id
                    WHERE r.book_id = :book_id
                    ORDER BY r.created_at DESC
                """, {"book_id": book_id})

                rows = cursor.fetchall()

        return [
            {
                "review_id": row[0],
                "user_id": row[1],
                "name": row[2],
                "rating": row[3],
                "review_text": row[4],
                "created_at": row[5].isoformat() if row[5] else None,
            }
            for row in rows
        ]

    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Could not load reviews: {exc}")


@app.post("/api/reviews", status_code=201)
def create_review(
    data: ReviewData,
    authorization: Optional[str] = Header(default=None),
):
    user_id = get_current_user_id(authorization)
    conn = None

    try:
        conn = get_connection()

        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT book_id FROM BW_BOOKS WHERE book_id = :book_id",
                {"book_id": data.book_id},
            )
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="Book not found.")

            cursor.execute("""
                INSERT INTO BW_REVIEWS
                    (user_id, book_id, rating, review_text, created_at)
                VALUES
                    (:user_id, :book_id, :rating, :review_text, :created_at)
            """, {
                "user_id": user_id,
                "book_id": data.book_id,
                "rating": data.rating,
                "review_text": data.review_text.strip(),
                "created_at": datetime.now(timezone.utc).replace(tzinfo=None),
            })

        conn.commit()
        return {"message": "Review submitted successfully."}

    except HTTPException:
        if conn:
            conn.rollback()
        raise

    except Exception as exc:
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail=f"Could not submit review: {exc}")

    finally:
        if conn:
            conn.close()
