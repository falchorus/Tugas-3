from __future__ import annotations

import os
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, Blueprint, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    get_jwt,
    verify_jwt_in_request
)
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()
jwt = JWTManager()

# ==============================================================================
# Model Database
# ==============================================================================
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'merchant' atau 'user'

    merchant = db.relationship('Merchant', backref='owner', uselist=False, cascade='all, delete-orphan')
    claims = db.relationship('Claim', backref='buyer', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "role": self.role
        }


class Merchant(db.Model):
    __tablename__ = 'merchants'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, nullable=False)
    store_name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    address = db.Column(db.Text, nullable=True)
    phone = db.Column(db.String(20), nullable=True)

    products = db.relationship('Product', backref='merchant', lazy=True, cascade='all, delete-orphan')

    def to_dict(self, include_products=False):
        data = {
            "id": self.id,
            "user_id": self.user_id,
            "store_name": self.store_name,
            "description": self.description or "",
            "address": self.address or "",
            "phone": self.phone or ""
        }
        if include_products:
            data["products"] = [p.to_dict() for p in self.products]
        return data


class Product(db.Model):
    __tablename__ = 'products'

    id = db.Column(db.Integer, primary_key=True)
    merchant_id = db.Column(db.Integer, db.ForeignKey('merchants.id'), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False)

    claims = db.relationship('Claim', backref='product', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            "id": self.id,
            "merchant_id": self.merchant_id,
            "name": self.name,
            "description": self.description or "",
            "price": self.price,
            "stock": self.stock,
            "store_name": self.merchant.store_name if self.merchant else None
        }


class Claim(db.Model):
    __tablename__ = 'claims'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)

    def to_dict(self):
        return {
            "id": self.id,
            "buyer_id": self.user_id,
            "buyer_name": self.buyer.name if self.buyer else None,
            "product_id": self.product_id,
            "product_name": self.product.name if self.product else None,
            "quantity": self.quantity,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


# ==============================================================================
# Helper Respon Standar
# ==============================================================================
def response_json(success, message, data=None, status_code=200):
    payload = {"success": success, "message": message}
    if data is not None:
        payload["data"] = data
    return jsonify(payload), status_code


# ==============================================================================
# Decorator Otorisasi Role
# ==============================================================================
def role_required(required_role):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                verify_jwt_in_request()
            except Exception as e:
                return response_json(False, f"Token otorisasi diperlukan atau tidak valid: {str(e)}", status_code=401)

            claims = get_jwt()
            if claims.get("role") != required_role:
                return response_json(False, f"Akses ditolak: Hanya role '{required_role}' yang diperbolehkan", status_code=403)

            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ==============================================================================
# Blueprints
# ==============================================================================
auth_bp = Blueprint('auth', __name__)
merchants_bp = Blueprint('merchants', __name__)
products_bp = Blueprint('products', __name__)
claims_bp = Blueprint('claims', __name__)


# ==============================================================================
# Endpoint Auth
# ==============================================================================
@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json(silent=True) or {}
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role')

    if not name or not str(name).strip():
        return response_json(False, "Field name wajib diisi", status_code=400)
    if not email or not str(email).strip():
        return response_json(False, "Field email wajib diisi", status_code=400)
    if not password or not str(password).strip():
        return response_json(False, "Field password wajib diisi", status_code=400)
    if not role or not str(role).strip():
        return response_json(False, "Field role wajib diisi", status_code=400)

    name = str(name).strip()
    email = str(email).strip().lower()
    password = str(password)
    role = str(role).strip().lower()

    if role not in ['merchant', 'user']:
        return response_json(False, "Role harus 'merchant' atau 'user'", status_code=400)

    if User.query.filter_by(email=email).first():
        return response_json(False, "Email sudah terdaftar", status_code=409)

    hashed_pw = generate_password_hash(password)
    new_user = User(name=name, email=email, password_hash=hashed_pw, role=role)
    db.session.add(new_user)
    db.session.commit()

    return response_json(True, "Registrasi berhasil", new_user.to_dict(), status_code=201)


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return response_json(False, "Email dan password wajib diisi", status_code=400)

    email = str(email).strip().lower()
    password = str(password)

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return response_json(False, "Email atau password salah", status_code=401)

    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={"role": user.role}
    )

    return response_json(True, "Login berhasil", {
        "token": access_token,
        "user": user.to_dict()
    }, status_code=200)


@auth_bp.route('/me', methods=['GET'])
@auth_bp.route('/profile', methods=['GET'])
def get_current_user():
    try:
        verify_jwt_in_request()
    except Exception as e:
        return response_json(False, f"Token otorisasi diperlukan: {str(e)}", status_code=401)

    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)
    if not user:
        return response_json(False, "User tidak ditemukan", status_code=404)

    return response_json(True, "Berhasil mengambil data profil", user.to_dict())


# ==============================================================================
# Endpoint Merchants
# ==============================================================================
@merchants_bp.route('/merchants', methods=['POST'])
@role_required('merchant')
def create_merchant():
    user_id = int(get_jwt_identity())

    if Merchant.query.filter_by(user_id=user_id).first():
        return response_json(False, "Merchant hanya boleh memiliki satu profil toko", status_code=400)

    data = request.get_json(silent=True) or {}
    store_name = data.get('store_name')

    if not store_name or not str(store_name).strip():
        return response_json(False, "store_name wajib diisi", status_code=400)

    store_name = str(store_name).strip()

    if Merchant.query.filter_by(store_name=store_name).first():
        return response_json(False, "Nama toko sudah digunakan", status_code=409)

    merchant = Merchant(
        user_id=user_id,
        store_name=store_name,
        description=str(data.get('description', '')).strip(),
        address=str(data.get('address', '')).strip(),
        phone=str(data.get('phone', '')).strip()
    )
    db.session.add(merchant)
    db.session.commit()

    return response_json(True, "Toko berhasil dibuat", merchant.to_dict(), status_code=201)


@merchants_bp.route('/merchants/me', methods=['GET'])
@role_required('merchant')
def get_my_merchant():
    user_id = int(get_jwt_identity())
    merchant = Merchant.query.filter_by(user_id=user_id).first()

    if not merchant:
        return response_json(False, "Profil toko belum dibuat", status_code=404)

    return response_json(True, "Berhasil mengambil profil toko", merchant.to_dict(include_products=True))


@merchants_bp.route('/merchants/me', methods=['PUT'])
@role_required('merchant')
def update_my_merchant():
    user_id = int(get_jwt_identity())
    merchant = Merchant.query.filter_by(user_id=user_id).first()

    if not merchant:
        return response_json(False, "Profil toko tidak ditemukan", status_code=404)

    data = request.get_json(silent=True) or {}

    if 'store_name' in data:
        store_name = str(data['store_name']).strip()
        if not store_name:
            return response_json(False, "Nama toko tidak boleh kosong", status_code=400)
        if store_name != merchant.store_name:
            existing = Merchant.query.filter_by(store_name=store_name).first()
            if existing and existing.id != merchant.id:
                return response_json(False, "Nama toko sudah digunakan", status_code=409)
            merchant.store_name = store_name

    if 'description' in data:
        merchant.description = str(data['description']).strip()
    if 'address' in data:
        merchant.address = str(data['address']).strip()
    if 'phone' in data:
        merchant.phone = str(data['phone']).strip()

    db.session.commit()

    return response_json(True, "Profil toko berhasil diperbarui", merchant.to_dict())


@merchants_bp.route('/merchants', methods=['GET'])
def get_all_merchants():
    merchants = Merchant.query.all()
    return response_json(True, "Berhasil mengambil daftar toko", [m.to_dict() for m in merchants])


@merchants_bp.route('/merchants/<int:merchant_id>', methods=['GET'])
def get_merchant_detail(merchant_id):
    merchant = db.session.get(Merchant, merchant_id)
    if not merchant:
        return response_json(False, "Toko tidak ditemukan", status_code=404)

    return response_json(True, "Berhasil mengambil detail toko", merchant.to_dict(include_products=True))


# ==============================================================================
# Endpoint Products
# ==============================================================================
@products_bp.route('/products', methods=['POST'])
@role_required('merchant')
def create_product():
    user_id = int(get_jwt_identity())
    merchant = Merchant.query.filter_by(user_id=user_id).first()

    if not merchant:
        return response_json(False, "Anda harus membuat profil toko terlebih dahulu sebelum menambah produk", status_code=400)

    data = request.get_json(silent=True) or {}
    name = data.get('name')
    price = data.get('price')
    stock = data.get('stock')

    if name is None or price is None or stock is None:
        return response_json(False, "Field name, price, dan stock wajib diisi", status_code=400)

    name = str(name).strip()
    if not name:
        return response_json(False, "Field name tidak boleh kosong", status_code=400)

    try:
        if isinstance(price, bool):
            raise ValueError
        price_val = float(price)
        if price_val < 0:
            return response_json(False, "Harga (price) tidak boleh negatif", status_code=400)
    except (ValueError, TypeError):
        return response_json(False, "Harga (price) harus berupa angka valid", status_code=400)

    try:
        if isinstance(stock, bool):
            raise ValueError
        stock_val = int(stock)
        if float(stock) != stock_val or stock_val < 0:
            return response_json(False, "Stok (stock) tidak boleh negatif dan harus berupa integer", status_code=400)
    except (ValueError, TypeError):
        return response_json(False, "Stok (stock) tidak boleh negatif dan harus berupa integer", status_code=400)

    product = Product(
        merchant_id=merchant.id,
        name=name,
        description=str(data.get('description', '')).strip(),
        price=price_val,
        stock=stock_val
    )
    db.session.add(product)
    db.session.commit()

    return response_json(True, "Produk berhasil ditambahkan", product.to_dict(), status_code=201)


@products_bp.route('/products', methods=['GET'])
def get_all_products():
    return get_catalog()


@products_bp.route('/products/<int:product_id>', methods=['GET'])
def get_single_product(product_id):
    return get_catalog_detail(product_id)


@products_bp.route('/products/mine', methods=['GET'])
@products_bp.route('/products/me', methods=['GET'])
@role_required('merchant')
def get_my_products():
    user_id = int(get_jwt_identity())
    merchant = Merchant.query.filter_by(user_id=user_id).first()

    if not merchant:
        return response_json(False, "Profil toko belum dibuat", status_code=400)

    products = Product.query.filter_by(merchant_id=merchant.id).all()
    return response_json(True, "Berhasil mengambil produk milik sendiri", [p.to_dict() for p in products])


@products_bp.route('/products/<int:product_id>', methods=['PUT'])
@role_required('merchant')
def update_product(product_id):
    user_id = int(get_jwt_identity())
    merchant = Merchant.query.filter_by(user_id=user_id).first()

    if not merchant:
        return response_json(False, "Profil toko belum dibuat", status_code=400)

    product = db.session.get(Product, product_id)
    if not product:
        return response_json(False, "Produk tidak ditemukan", status_code=404)

    if product.merchant_id != merchant.id:
        return response_json(False, "Anda tidak memiliki akses untuk merubah produk di toko lain", status_code=403)

    data = request.get_json(silent=True) or {}

    if 'name' in data:
        name = str(data['name']).strip()
        if not name:
            return response_json(False, "Field name tidak boleh kosong", status_code=400)
        product.name = name

    if 'description' in data:
        product.description = str(data['description']).strip()

    if 'price' in data:
        try:
            if isinstance(data['price'], bool):
                raise ValueError
            price_val = float(data['price'])
            if price_val < 0:
                return response_json(False, "Harga (price) tidak boleh negatif", status_code=400)
            product.price = price_val
        except (ValueError, TypeError):
            return response_json(False, "Harga (price) harus berupa angka valid", status_code=400)

    if 'stock' in data:
        try:
            if isinstance(data['stock'], bool):
                raise ValueError
            stock_val = int(data['stock'])
            if float(data['stock']) != stock_val or stock_val < 0:
                return response_json(False, "Stok (stock) tidak boleh negatif dan harus berupa integer", status_code=400)
            product.stock = stock_val
        except (ValueError, TypeError):
            return response_json(False, "Stok (stock) tidak boleh negatif dan harus berupa integer", status_code=400)

    db.session.commit()

    return response_json(True, "Produk berhasil diperbarui", product.to_dict())


@products_bp.route('/products/<int:product_id>', methods=['DELETE'])
@role_required('merchant')
def delete_product(product_id):
    user_id = int(get_jwt_identity())
    merchant = Merchant.query.filter_by(user_id=user_id).first()

    if not merchant:
        return response_json(False, "Profil toko belum dibuat", status_code=400)

    product = db.session.get(Product, product_id)
    if not product:
        return response_json(False, "Produk tidak ditemukan", status_code=404)

    if product.merchant_id != merchant.id:
        return response_json(False, "Anda tidak memiliki akses untuk menghapus produk di toko lain", status_code=403)

    db.session.delete(product)
    db.session.commit()

    return response_json(True, "Produk berhasil dihapus")


# ==============================================================================
# Endpoint Catalog & Claims
# ==============================================================================
@claims_bp.route('/catalog', methods=['GET'])
def get_catalog():
    search = request.args.get('search', type=str)
    merchant_id = request.args.get('merchant_id', type=int)

    try:
        page = int(request.args.get('page', 1))
        if page < 1:
            page = 1
    except (ValueError, TypeError):
        page = 1

    try:
        per_page = int(request.args.get('per_page', 10))
        if per_page < 1:
            per_page = 10
        elif per_page > 100:
            per_page = 100
    except (ValueError, TypeError):
        per_page = 10

    query = Product.query.filter(Product.stock > 0)

    if search and search.strip():
        query = query.filter(Product.name.ilike(f"%{search.strip()}%"))

    if merchant_id:
        query = query.filter(Product.merchant_id == merchant_id)

    paginated = query.paginate(page=page, per_page=per_page, error_out=False)

    return response_json(True, "Berhasil mengambil katalog produk", {
        "items": [p.to_dict() for p in paginated.items],
        "total": paginated.total,
        "page": paginated.page,
        "per_page": paginated.per_page,
        "pages": paginated.pages
    })


@claims_bp.route('/catalog/<int:product_id>', methods=['GET'])
def get_catalog_detail(product_id):
    product = db.session.get(Product, product_id)
    if not product:
        return response_json(False, "Produk tidak ditemukan", status_code=404)

    return response_json(True, "Berhasil mengambil detail produk", product.to_dict())


@claims_bp.route('/claims', methods=['POST'])
@role_required('user')
def claim_product():
    user_id = int(get_jwt_identity())
    data = request.get_json(silent=True) or {}

    product_id = data.get('product_id')
    quantity = data.get('quantity')

    if product_id is None or quantity is None:
        return response_json(False, "product_id dan quantity wajib diisi", status_code=400)

    try:
        if isinstance(product_id, bool):
            raise ValueError
        product_id = int(product_id)
    except (ValueError, TypeError):
        return response_json(False, "product_id harus berupa integer valid", status_code=400)

    try:
        if isinstance(quantity, bool):
            raise ValueError
        quantity = int(quantity)
        if quantity <= 0:
            return response_json(False, "quantity harus angka bulat positif", status_code=400)
    except (ValueError, TypeError):
        return response_json(False, "quantity harus angka bulat positif", status_code=400)

    product = db.session.get(Product, product_id)
    if not product:
        return response_json(False, "Produk tidak ditemukan", status_code=404)

    if quantity > product.stock:
        return response_json(False, "Stok tidak mencukupi", status_code=400)

    product.stock -= quantity

    claim = Claim(
        user_id=user_id,
        product_id=product_id,
        quantity=quantity
    )
    db.session.add(claim)
    db.session.commit()

    return response_json(True, "Produk berhasil diambil", claim.to_dict(), status_code=201)


@claims_bp.route('/claims', methods=['GET'])
@role_required('user')
def get_my_claims():
    user_id = int(get_jwt_identity())
    claims = Claim.query.filter_by(user_id=user_id).order_by(Claim.created_at.desc()).all()
    return response_json(True, "Berhasil mengambil riwayat claim", [c.to_dict() for c in claims])


@claims_bp.route('/merchant/claims', methods=['GET'])
@claims_bp.route('/merchants/claims', methods=['GET'])
@claims_bp.route('/claims/merchant', methods=['GET'])
@role_required('merchant')
def get_merchant_claims():
    user_id = int(get_jwt_identity())
    merchant = Merchant.query.filter_by(user_id=user_id).first()

    if not merchant:
        return response_json(False, "Profil toko belum dibuat", status_code=400)

    claims = Claim.query.join(Product).filter(Product.merchant_id == merchant.id).order_by(Claim.created_at.desc()).all()
    return response_json(True, "Berhasil mengambil daftar claim toko", [c.to_dict() for c in claims])


# ==============================================================================
# Application Factory
# ==============================================================================
def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'super-secret-key-change-this')
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key-change-this')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)

    base_dir = os.path.abspath(os.path.dirname(__file__))
    sqlite_path = os.path.join(base_dir, 'toko_multi_merchant.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', f'sqlite:///{sqlite_path}')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    jwt.init_app(app)

    @jwt.unauthorized_loader
    def unauthorized_callback(callback):
        return response_json(False, f"Token otorisasi diperlukan: {callback}", status_code=401)

    @jwt.invalid_token_loader
    def invalid_token_callback(callback):
        return response_json(False, f"Token tidak valid: {callback}", status_code=401)

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return response_json(False, "Token telah kedaluwarsa, silakan login kembali", status_code=401)

    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        return response_json(False, "Token telah dicabut", status_code=401)

    @app.errorhandler(400)
    def handle_bad_request(error):
        return response_json(False, "Bad request atau data JSON tidak valid", status_code=400)

    @app.errorhandler(404)
    def handle_not_found(error):
        return response_json(False, "Data atau endpoint tidak ditemukan", status_code=404)

    @app.errorhandler(405)
    def handle_method_not_allowed(error):
        return response_json(False, "Metode HTTP tidak diizinkan untuk endpoint ini", status_code=405)

    @app.errorhandler(500)
    def handle_server_error(error):
        db.session.rollback()
        return response_json(False, "Terjadi kesalahan internal server", status_code=500)

    app.register_blueprint(auth_bp, url_prefix='/api')
    app.register_blueprint(merchants_bp, url_prefix='/api')
    app.register_blueprint(products_bp, url_prefix='/api')
    app.register_blueprint(claims_bp, url_prefix='/api')

    with app.app_context():
        db.create_all()

    return app


app = create_app()

if __name__ == '__main__':
    print(f"[OK] Database aktif: {app.config['SQLALCHEMY_DATABASE_URI']}")
    app.run(debug=True, port=5000)