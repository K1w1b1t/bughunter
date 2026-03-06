from __future__ import annotations

import asyncio
from typing import Any

from fastapi import FastAPI, Query

app = FastAPI(title="HunterOps Mock API")

_USERS: dict[int, dict[str, Any]] = {
    1: {"user_id": 1, "email": "owner@example.com", "role": "user"},
    2: {"user_id": 2, "email": "victim@example.com", "role": "user"},
}
_WALLET_STATE = {"balance": 10, "withdraw_count": 0}


@app.get("/api/v1/profile")
async def idor_profile(user_id: int = Query(...)) -> dict[str, Any]:
    # Intentionally vulnerable: no ownership check.
    return _USERS.get(user_id, {"user_id": user_id, "email": "unknown@example.com"})


@app.get("/api/cart")
async def cart(price: float = Query(100.0), quantity: int = Query(1)) -> dict[str, Any]:
    # Intentionally vulnerable: accepts negative and near-zero values.
    total = price * quantity
    return {
        "status": "success",
        "price": price,
        "quantity": quantity,
        "total": total,
        "transaction_id": f"txn_{abs(int(total * 10))}",
    }


@app.get("/api/success")
async def success() -> dict[str, Any]:
    # Intentionally vulnerable state machine endpoint.
    return {"status": "success", "message": "order confirmed without payment"}


@app.get("/api/wallet/withdraw")
async def withdraw(amount: int = Query(1)) -> dict[str, Any]:
    # Intentionally vulnerable: check/use race by delaying deduction.
    if amount <= 0:
        return {"ok": False, "error": "invalid amount"}
    if _WALLET_STATE["balance"] < amount:
        return {"ok": False, "error": "insufficient"}
    await asyncio.sleep(0.025)
    _WALLET_STATE["balance"] -= amount
    _WALLET_STATE["withdraw_count"] += 1
    return {
        "ok": True,
        "balance": _WALLET_STATE["balance"],
        "transaction_id": f"wallet_{_WALLET_STATE['withdraw_count']}",
    }


@app.get("/api/coupon/apply")
async def coupon_apply(coupon: list[str] = Query(default=[])) -> dict[str, Any]:
    # Intentionally vulnerable: accepts stacked coupon arrays.
    discount = len(coupon) * 10
    return {"status": "success", "coupon_count": len(coupon), "discount": discount}

