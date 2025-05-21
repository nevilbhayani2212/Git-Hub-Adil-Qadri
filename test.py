import hashlib

SECRET_KEY = "abcd123456987"  

def encode_order_id(order_id: int) -> str:
    data = f"{order_id}-{SECRET_KEY}"
    return hashlib.sha256(data.encode()).hexdigest()[:16] 

def decode_and_validate_order_id(encoded_id: str, order_id: int) -> bool:
    expected_hash = encode_order_id(order_id)
    return encoded_id == expected_hash

order_id = 1
encoded = encode_order_id(order_id)
print("Encoded ID:", encoded)

is_valid = decode_and_validate_order_id(encoded, order_id)
print("Is valid:", is_valid)