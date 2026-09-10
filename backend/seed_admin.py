import sys
from sqlalchemy.orm import Session
from app.db.database import SessionLocal, engine, Base
from app.db import models
from app.core import security

def seed():
    # Ensure tables exist
    Base.metadata.create_all(bind=engine)
    
    db: Session = SessionLocal()
    try:
        # Check if admin already exists
        admin_exists = db.query(models.User).filter_by(username="blackholeadmin").first()
        if admin_exists:
            print("[*] Admin user 'blackholeadmin' already exists.")
            return

        # Build clean admin schema
        admin_user = models.User(
            username="blackholeadmin",
            email="admin@blackhole.cyber",
            hashed_password=security.hash_password("raR#678@wns"),
            role=models.Role.ADMIN if hasattr(models.Role, "ADMIN") else "admin",
            is_active=True
        )
        
        db.add(admin_user)
        db.commit()
        print("[+] Success: 'blackholeadmin' successfully added to Blackhole database!")
        
    except Exception as e:
        print(f"[-] Error seeding database: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    seed()
