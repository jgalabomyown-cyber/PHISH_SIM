from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    # Fallback configuration structures
    database_url: str = "postgresql://blackhole:blackholepass@db:5432/blackhole"
    secret_key: str = "fallback-insecure-dev-key-replace-in-env"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    
    # Critical Lifespan Environment Keys (Kept empty/safe here, read directly from .env!)
    first_admin_username: str = "blackholeadmin"
    first_admin_password: str = ""
    
    public_base_url: str = "http://localhost:8000"   # victims' clickable base URL
    
    # Structural module paths
    oob_domain: str = "oob.blackhole.local"        
    payload_dir: str = "/app/payloads"             
    ollama_url: str = "http://ollama:11434"        

    # Modern environment mapping structure
    model_config = SettingsConfigDict(
        env_file=".env", 
        env_file_encoding="utf-8", 
        extra="ignore"
    )

settings = Settings()
