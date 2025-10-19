import time
import traceback
from app import send_due_reminders

def sleep_until_next_minute():
    now = time.time()
    secs = 60 - (int(now) % 60)
    time.sleep(secs)

if __name__ == "__main__":
    print("[always-on] starting reminder loop")
    sleep_until_next_minute()
    while True:
        try:
            send_due_reminders()
        except Exception:
            traceback.print_exc()
        finally:
            time.sleep(60)
