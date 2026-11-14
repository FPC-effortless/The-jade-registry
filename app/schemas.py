from datetime import date
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator

COUNTRIES = {"SG", "JP", "KR", "CN", "IN", "MY", "HK", "TW", "TH", "ID", "PH", "VN", "GB", "US", "AU", "CA", "NZ", "AE", "NG"}


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Login(Input):
    email: str = Field(min_length=5, max_length=254, pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
    password: str = Field(min_length=12, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize(cls, value):
        return value.lower()


class ProfileIn(Input):
    display_name: str = Field(min_length=1, max_length=90)
    birth_date: date
    country: str
    looking_in: str
    marriage_intent: bool = True
    discoverable: bool = False

    @field_validator("display_name")
    @classmethod
    def clean_name(cls, value):
        value = value.strip()
        if not value or any(ord(c) < 32 for c in value):
            raise ValueError("Enter a valid display name")
        return value

    @field_validator("country", "looking_in")
    @classmethod
    def country_code(cls, value):
        if value not in COUNTRIES:
            raise ValueError("Unsupported country code")
        return value


class ConsentIn(Input):
    matchmaking: bool
    profile_sharing: bool


class IntroductionIn(Input):
    first_id: int = Field(gt=0)
    second_id: int = Field(gt=0)


class Decision(Input):
    accept: bool


class Review(Input):
    approved: bool
    evidence_reference: str = Field(min_length=5, max_length=160)

    @field_validator("evidence_reference")
    @classmethod
    def reference(cls, value):
        value = value.strip()
        if len(value) < 5:
            raise ValueError("Provide an internal review reference, not identity-document details")
        return value


class ReportIn(Input):
    member_id: int = Field(gt=0)
    category: Literal["impersonation", "harassment", "fraud", "other"]
    description: str = Field(min_length=10, max_length=2000)


class ReportDecision(Input):
    status: Literal["reviewing", "closed"]
