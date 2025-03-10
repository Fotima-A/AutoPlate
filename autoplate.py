from fastapi import FastAPI, Depends, HTTPException, Security, Path, Query, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Boolean, DECIMAL, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
import datetime
from typing import List, Optional
from pydantic import BaseModel, validator, Field, condecimal
import jwt
from passlib.context import CryptContext

DATABASE_URL = "sqlite:///./auto_plate.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

SECRET_KEY = "supersecretkey"
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_password_hash(password):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    is_staff = Column(Boolean, default=False)
    bids = relationship("Bid", backref="user")
    plates_created = relationship("AutoPlate", backref="creator")


class AutoPlate(Base):
    __tablename__ = "auto_plates"
    id = Column(Integer, primary_key=True, index=True)
    plate_number = Column(String(10), unique=True, index=True)
    description = Column(String)
    deadline = Column(DateTime)
    created_by = Column(Integer, ForeignKey("users.id"))
    is_active = Column(Boolean, default=True)
    bids = relationship("Bid", backref="plate", cascade="all, delete-orphan")


class Bid(Base):
    __tablename__ = "bids"
    id = Column(Integer, primary_key=True, index=True)
    amount = Column(DECIMAL(10, 2))
    user_id = Column(Integer, ForeignKey("users.id"))
    plate_id = Column(Integer, ForeignKey("auto_plates.id"))
    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        {'sqlite_autoincrement': True},
    )


Base.metadata.create_all(bind=engine)


class Token(BaseModel):
    token: str


class LoginRequest(BaseModel):
    username: str
    password: str


class BidBase(BaseModel):
    amount: condecimal(ge=0, decimal_places=2)


class BidCreate(BidBase):
    plate_id: int

    @validator('amount')
    def amount_must_be_positive(cls, v):
        if v <= 0:
            raise ValueError('Amount must be positive')
        return v


class BidUpdate(BidBase):
    pass


class BidResponse(BidBase):
    id: int
    plate_id: int
    created_at: datetime.datetime

    class Config:
        orm_mode = True


class BidDetail(BidResponse):
    user_id: int


class PlateBase(BaseModel):
    plate_number: str
    description: str
    deadline: datetime.datetime

    @validator('deadline')
    def deadline_must_be_future(cls, v):
        if v <= datetime.datetime.now():
            raise ValueError('Deadline must be in the future')
        return v

    @validator('plate_number')
    def plate_number_valid(cls, v):
        if len(v) > 10:
            raise ValueError('Plate number can be at most 10 characters')
        return v


class PlateCreate(PlateBase):
    pass


class PlateUpdate(PlateBase):
    pass


class PlateResponse(PlateBase):
    id: int
    created_by: int
    is_active: bool
    highest_bid: Optional[float] = None

    class Config:
        orm_mode = True


class PlateDetail(PlateResponse):
    bids: List[BidDetail] = []


app = FastAPI()

@app.post("/login/", response_model=Token)
def login(login_data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == login_data.username).first()
    if not user or not verify_password(login_data.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    expire = datetime.datetime.utcnow() + datetime.timedelta(hours=1)

    token_payload = {
        "sub": str(user.id),
        "is_staff": user.is_staff,
        "exp": expire
    }

    token = jwt.encode(token_payload, SECRET_KEY, algorithm="HS256")
    return {"token": token}


def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security), db: Session = Depends(get_db)):
    token = credentials.credentials

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = int(payload["sub"])

        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")

        is_staff_from_token = payload.get("is_staff", False)

        if user.is_staff != is_staff_from_token:
            user.is_staff = is_staff_from_token
            db.commit()

        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Authentication error: {str(e)}")


def get_admin_user(current_user: User = Depends(get_current_user)):
    if not current_user.is_staff:
        raise HTTPException(
            status_code=403,
            detail="Admin privileges required. Your account is not marked as staff."
        )
    return current_user


@app.post("/register/", status_code=status.HTTP_201_CREATED)
def register_user(
        username: str,
        email: str,
        password: str,
        is_staff: bool = False,
        db: Session = Depends(get_db)
):
    existing_user = db.query(User).filter(
        (User.username == username) | (User.email == email)
    ).first()

    if existing_user:
        raise HTTPException(status_code=400, detail="Username or email already exists")

    hashed_password = get_password_hash(password)
    user = User(
        username=username,
        email=email,
        password=hashed_password,
        is_staff=is_staff
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return {"message": "User registered successfully"}


@app.get("/plates/", response_model=List[PlateResponse])
def get_plates(
        ordering: Optional[str] = Query(None, description="Order by deadline"),
        plate_number__contains: Optional[str] = Query(None, description="Filter by plate number"),
        db: Session = Depends(get_db)
):
    query = db.query(AutoPlate)
    if plate_number__contains:
        query = query.filter(AutoPlate.plate_number.contains(plate_number__contains))
    if ordering == "deadline":
        query = query.order_by(AutoPlate.deadline)
    plates = query.all()

    result = []
    for plate in plates:
        highest_bid = db.query(func.max(Bid.amount)).filter(Bid.plate_id == plate.id).scalar()
        plate_dict = {
            "id": plate.id,
            "plate_number": plate.plate_number,
            "description": plate.description,
            "deadline": plate.deadline,
            "created_by": plate.created_by,
            "is_active": plate.is_active,
            "highest_bid": float(highest_bid) if highest_bid else None
        }
        result.append(plate_dict)

    return result


@app.post("/plates/", response_model=PlateResponse, status_code=status.HTTP_201_CREATED)
def create_plate(
        plate_data: PlateCreate,
        current_user: User = Depends(get_admin_user),
        db: Session = Depends(get_db)
):
    existing_plate = db.query(AutoPlate).filter(AutoPlate.plate_number == plate_data.plate_number).first()
    if existing_plate:
        raise HTTPException(status_code=400, detail="Plate number already exists")

    plate = AutoPlate(
        plate_number=plate_data.plate_number,
        description=plate_data.description,
        deadline=plate_data.deadline,
        created_by=current_user.id
    )
    db.add(plate)
    db.commit()
    db.refresh(plate)

    return {
        "id": plate.id,
        "plate_number": plate.plate_number,
        "description": plate.description,
        "deadline": plate.deadline,
        "created_by": plate.created_by,
        "is_active": plate.is_active,
        "highest_bid": None
    }


@app.get("/plates/{plate_id}/", response_model=PlateDetail)
def get_plate(
        plate_id: int = Path(..., gt=0),
        db: Session = Depends(get_db)
):
    plate = db.query(AutoPlate).filter(AutoPlate.id == plate_id).first()
    if not plate:
        raise HTTPException(status_code=404, detail="Plate not found")

    bids = db.query(Bid).filter(Bid.plate_id == plate.id).all()
    bid_list = []
    for bid in bids:
        bid_list.append({
            "id": bid.id,
            "amount": float(bid.amount),
            "user_id": bid.user_id,
            "plate_id": bid.plate_id,
            "created_at": bid.created_at
        })

    highest_bid = db.query(func.max(Bid.amount)).filter(Bid.plate_id == plate.id).scalar()

    return {
        "id": plate.id,
        "plate_number": plate.plate_number,
        "description": plate.description,
        "deadline": plate.deadline,
        "created_by": plate.created_by,
        "is_active": plate.is_active,
        "highest_bid": float(highest_bid) if highest_bid else None,
        "bids": bid_list
    }


@app.put("/plates/{plate_id}/", response_model=PlateResponse)
def update_plate(
        plate_data: PlateUpdate,
        plate_id: int = Path(..., gt=0),
        current_user: User = Depends(get_admin_user),
        db: Session = Depends(get_db)
):
    plate = db.query(AutoPlate).filter(AutoPlate.id == plate_id).first()
    if not plate:
        raise HTTPException(status_code=404, detail="Plate not found")

    existing_plate = db.query(AutoPlate).filter(
        AutoPlate.plate_number == plate_data.plate_number,
        AutoPlate.id != plate_id
    ).first()
    if existing_plate:
        raise HTTPException(status_code=400, detail="Plate number already exists")

    plate.plate_number = plate_data.plate_number
    plate.description = plate_data.description
    plate.deadline = plate_data.deadline

    db.commit()
    db.refresh(plate)

    highest_bid = db.query(func.max(Bid.amount)).filter(Bid.plate_id == plate.id).scalar()

    return {
        "id": plate.id,
        "plate_number": plate.plate_number,
        "description": plate.description,
        "deadline": plate.deadline,
        "created_by": plate.created_by,
        "is_active": plate.is_active,
        "highest_bid": float(highest_bid) if highest_bid else None
    }


@app.delete("/plates/{plate_id}/", status_code=status.HTTP_204_NO_CONTENT)
def delete_plate(
        plate_id: int = Path(..., gt=0),
        current_user: User = Depends(get_admin_user),
        db: Session = Depends(get_db)
):
    plate = db.query(AutoPlate).filter(AutoPlate.id == plate_id).first()
    if not plate:
        raise HTTPException(status_code=404, detail="Plate not found")

    db.delete(plate)
    db.commit()

    return None


# Bid Endpoints
@app.get("/bids/", response_model=List[BidResponse])
def get_user_bids(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    bids = db.query(Bid).filter(Bid.user_id == current_user.id).all()

    result = []
    for bid in bids:
        bid_dict = {
            "id": bid.id,
            "amount": float(bid.amount),
            "plate_id": bid.plate_id,
            "created_at": bid.created_at
        }
        result.append(bid_dict)

    return result


@app.post("/bids/", response_model=BidResponse, status_code=status.HTTP_201_CREATED)
def create_bid(
        bid_data: BidCreate,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    plate = db.query(AutoPlate).filter(AutoPlate.id == bid_data.plate_id).first()
    if not plate:
        raise HTTPException(status_code=404, detail="Plate not found")

    if not plate.is_active:
        raise HTTPException(status_code=400, detail="Bidding is closed for this plate")

    if plate.deadline < datetime.datetime.now():
        raise HTTPException(status_code=400, detail="Bidding deadline has passed")

    existing_bid = db.query(Bid).filter(
        Bid.user_id == current_user.id,
        Bid.plate_id == bid_data.plate_id
    ).first()

    if existing_bid:
        if float(existing_bid.amount) >= float(bid_data.amount):
            raise HTTPException(status_code=400, detail="New bid must be higher than your current bid")

        existing_bid.amount = bid_data.amount
        db.commit()
        db.refresh(existing_bid)

        return {
            "id": existing_bid.id,
            "amount": float(existing_bid.amount),
            "plate_id": existing_bid.plate_id,
            "created_at": existing_bid.created_at
        }
    else:
        highest_bid = db.query(func.max(Bid.amount)).filter(Bid.plate_id == bid_data.plate_id).scalar()
        if highest_bid and float(highest_bid) >= float(bid_data.amount):
            raise HTTPException(status_code=400, detail="Bid must be higher than the current highest bid")

        bid = Bid(
            amount=bid_data.amount,
            user_id=current_user.id,
            plate_id=bid_data.plate_id
        )
        db.add(bid)
        db.commit()
        db.refresh(bid)

        return {
            "id": bid.id,
            "amount": float(bid.amount),
            "plate_id": bid.plate_id,
            "created_at": bid.created_at
        }


@app.get("/bids/{bid_id}/", response_model=BidResponse)
def get_bid(
        bid_id: int = Path(..., gt=0),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    bid = db.query(Bid).filter(Bid.id == bid_id).first()
    if not bid:
        raise HTTPException(status_code=404, detail="Bid not found")

    if bid.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="You can only view your own bids")

    return {
        "id": bid.id,
        "amount": float(bid.amount),
        "plate_id": bid.plate_id,
        "created_at": bid.created_at
    }


@app.put("/bids/{bid_id}/", response_model=BidResponse)
def update_bid(
        bid_data: BidUpdate,
        bid_id: int = Path(..., gt=0),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    bid = db.query(Bid).filter(Bid.id == bid_id).first()
    if not bid:
        raise HTTPException(status_code=404, detail="Bid not found")

    if bid.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="You can only update your own bids")

    plate = db.query(AutoPlate).filter(AutoPlate.id == bid.plate_id).first()
    if not plate.is_active:
        raise HTTPException(status_code=400, detail="Bidding is closed for this plate")

    if plate.deadline < datetime.datetime.now():
        raise HTTPException(status_code=400, detail="Bidding deadline has passed")

    highest_other_bid = db.query(func.max(Bid.amount)).filter(
        Bid.plate_id == bid.plate_id,
        Bid.id != bid.id
    ).scalar()

    if highest_other_bid and float(highest_other_bid) >= float(bid_data.amount):
        raise HTTPException(status_code=400, detail="Bid must be higher than the current highest bid")

    if float(bid.amount) >= float(bid_data.amount):
        raise HTTPException(status_code=400, detail="New bid must be higher than your current bid")

    bid.amount = bid_data.amount
    db.commit()
    db.refresh(bid)

    return {
        "id": bid.id,
        "amount": float(bid.amount),
        "plate_id": bid.plate_id,
        "created_at": bid.created_at
    }


@app.delete("/bids/{bid_id}/", status_code=status.HTTP_204_NO_CONTENT)
def delete_bid(
        bid_id: int = Path(..., gt=0),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    bid = db.query(Bid).filter(Bid.id == bid_id).first()
    if not bid:
        raise HTTPException(status_code=404, detail="Bid not found")

    if bid.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="You can only delete your own bids")

    plate = db.query(AutoPlate).filter(AutoPlate.id == bid.plate_id).first()
    if plate.deadline < datetime.datetime.now():
        raise HTTPException(status_code=400, detail="Cannot delete bid after deadline has passed")

    db.delete(bid)
    db.commit()

    return None

@app.get("/me/", response_model=dict)
def get_my_info(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "is_staff": current_user.is_staff
    }