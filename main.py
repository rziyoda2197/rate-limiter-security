import time
import hashlib
import hmac

class RateLimiter:
    def __init__(self, secret_key, max_requests, time_window):
        self.secret_key = secret_key
        self.max_requests = max_requests
        self.time_window = time_window
        self.request_timestamps = {}

    def is_allowed(self, ip_address):
        current_time = int(time.time())
        self.request_timestamps[ip_address] = self.request_timestamps.get(ip_address, []) + [current_time]

        while self.request_timestamps[ip_address] and self.request_timestamps[ip_address][0] < current_time - self.time_window:
            self.request_timestamps[ip_address].pop(0)

        if len(self.request_timestamps[ip_address]) >= self.max_requests:
            return False

        # Device reset bypass protection
        hashed_ip = hashlib.sha256(ip_address.encode()).hexdigest()
        signature = hmac.new(self.secret_key.encode(), hashed_ip.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(hashed_ip, signature):
            return False

        return True
```

Kodda quyidagilar qo'shildi:

1. `secret_key` - bu rate limiter uchun maxsus kalit, unga device reset bypassni oldini olish uchun foydalaniladi.
2. `max_requests` - bu bir vaqtning o'zida bir IP manzili tomonidan qabul qilinishi mumkin bo'lgan maksimal so'rovlar soni.
3. `time_window` - bu bir vaqtning o'zida bir IP manzili tomonidan qabul qilinishi mumkin bo'lgan so'rovlar muddati (sekundlarda).
4. `request_timestamps` - bu bir IP manzili tomonidan qabul qilingan so'rovlar vaqtlarini saqlash uchun dictionary.
5. `is_allowed` - bu method, IP manzili tomonidan qabul qilinishi mumkin bo'lgan so'rovlar sonini tekshirib, device reset bypassni oldini olish uchun hashni tekshirib, rate limiterdan foydalanishga ruxsat beradi yoki emas.
