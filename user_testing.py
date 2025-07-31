import time
from faker import Faker
from app import app, db
from models import User
from crypto_utils import PKIManager
from werkzeug.security import generate_password_hash

fake = Faker()
user_counter = 0  # Global counter to ensure unique emails

def create_fake_user():
    global user_counter
    user_counter += 1

    username = fake.user_name() + str(user_counter)
    # Ensure globally unique email using the counter
    email = f"user{user_counter}_{fake.domain_name()}@example.com"
    password_hash = generate_password_hash("Benchmark@123")

    private_key_pem, public_key_pem = PKIManager.generate_key_pair()
    certificate_pem = PKIManager.create_certificate(username, email, public_key_pem)

    return User(
        username=username,
        email=email,
        password_hash=password_hash,
        private_key_pem=private_key_pem,
        public_key_pem=public_key_pem,
        certificate_pem=certificate_pem
    )

def benchmark_user_creation_batches(total_users=5000, batch_size=1000):
    with app.app_context():
        total_start = time.time()
        print(f"📊 Benchmarking user creation: {total_users} users in batches of {batch_size}")

        for batch in range(1, (total_users // batch_size) + 1):
            batch_start = time.time()

            for _ in range(batch_size):
                user = create_fake_user()
                db.session.add(user)

            try:
                db.session.commit()
            except Exception as e:
                print(f"❌ Error during batch {batch}: {e}")
                db.session.rollback()
                continue

            batch_end = time.time()
            elapsed = batch_end - batch_start
            print(f"✅ Batch {batch}: Inserted {batch_size} users in {elapsed:.2f} seconds "
                  f"({elapsed/batch_size:.4f} s/user)")

        total_elapsed = time.time() - total_start
        print(f"\n🎯 Completed {total_users} users in {total_elapsed:.2f} seconds")

if __name__ == "__main__":
    benchmark_user_creation_batches(total_users=5000, batch_size=1000)
