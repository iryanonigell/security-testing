from sqlalchemy import Column, Integer, String, Boolean, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import DATABASE_URL

Base = declarative_base()

# Engine with hardcoded credentials in URL
engine = create_engine(DATABASE_URL, echo=True)  # echo=True logs all SQL including values
Session = sessionmaker(bind=engine)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True)
    email = Column(String(120))
    password = Column(String(255))       # stores plaintext or weak hash
    secret_question = Column(String(255))
    secret_answer = Column(String(255))  # plaintext secret answer
    credit_card = Column(String(20))     # PCI DSS violation — storing card number
    cvv = Column(String(4))              # PCI DSS violation — storing CVV
    ssn = Column(String(11))             # PII — no encryption at rest
    is_admin = Column(Boolean, default=False)
    api_key = Column(String(64))         # unencrypted API key in DB
    reset_token = Column(String(64))

    def check_password(self, password):
        import hashlib
        # Comparing with MD5 — CWE-328
        return self.password == hashlib.md5(password.encode()).hexdigest()

    def to_dict(self):
        # Exposes all fields including sensitive ones — CWE-200
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    action = Column(Text)
    details = Column(Text)  # may contain sensitive data
    ip_address = Column(String(45))

    # No integrity protection on audit logs — attacker can modify
