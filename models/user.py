"""
User model for NOVUS authentication
"""
from flask_login import UserMixin
from werkzeug.security import check_password_hash

from utils.logger import logger


class User(UserMixin):
    """
    User model for authentication
    Supports multi-tenant architecture with company_id
    """

    def __init__(self, id, email, role='user', password=None, company_id=None):
        self.id = id
        self.email = email
        self.role = role
        self.password = password
        self.company_id = company_id

    def __repr__(self):
        return f'<User {self.email}>'

    def to_dict(self):
        """Convert user to dictionary"""
        return {
            'id': self.id,
            'email': self.email,
            'role': self.role,
            'company_id': self.company_id
        }

    @staticmethod
    def get_by_id(user_id):
        """Get user by ID from database"""
        if user_id is None or not str(user_id).isdigit():
            return None

        try:
            from services.auth_session_cache import get_cached_user, set_cached_user

            cached = get_cached_user(str(user_id))
            if cached is not None:
                return cached
        except Exception:
            pass

        try:
            from database import SessionLocal, Usuario

            db = SessionLocal()
            try:
                usuario = db.query(Usuario).filter(Usuario.id == int(user_id)).first()
                if not usuario or not usuario.is_active:
                    return None
                role = getattr(usuario, "role", None) or "analyst"
                user = User(
                    id=usuario.id,
                    email=usuario.email,
                    role=role,
                    company_id=usuario.nit_pyme
                )
                try:
                    from services.auth_session_cache import set_cached_user

                    set_cached_user(str(user_id), user)
                except Exception:
                    pass
                return user
            finally:
                db.close()
        except Exception as e:
            logger.error(f"Error loading user by id: {e}")
            return None

    @staticmethod
    def authenticate(email, password):
        """Authenticate user against database credentials"""
        if not email or not password:
            return None

        try:
            from database import SessionLocal, Usuario

            db = SessionLocal()
            try:
                usuario = db.query(Usuario).filter(
                    Usuario.email == email.strip().lower(),
                    Usuario.is_active == True
                ).first()
                if not usuario or not check_password_hash(usuario.hashed_password, password):
                    return None
                return User(
                    id=usuario.id,
                    email=usuario.email,
                    role=getattr(usuario, "role", None) or "analyst",
                    company_id=usuario.nit_pyme
                )
            finally:
                db.close()
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return None
