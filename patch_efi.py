import os, sys, binascii

file_path = sys.argv[1]
with open(file_path, "rb") as f:
    data = f.read()

# 替换公钥
keys = [
    ('MIKRO_NPK_SIGN_PUBLIC_KEY', 'CUSTOM_NPK_SIGN_PUBLIC_KEY'),
    ('MIKRO_LICENSE_PUBLIC_KEY', 'CUSTOM_LICENSE_PUBLIC_KEY'),
    ('MIKRO_CLOUD_PUBLIC_KEY', 'CUSTOM_CLOUD_PUBLIC_KEY')
]
for old_env, new_env in keys:
    old_val = os.environ.get(old_env)
    new_val = os.environ.get(new_env)
    if old_val and new_val:
        old_b = binascii.unhexlify(old_val)
        new_b = binascii.unhexlify(new_val)
        if old_b in data:
            data = data.replace(old_b, new_b)
            print(f"✅ 成功替换公钥: {old_env}")

# 替换 URL
urls = [
    ('MIKRO_UPGRADE_URL', 'CUSTOM_UPGRADE_URL'),
    ('MIKRO_CLOUD_URL', 'CUSTOM_CLOUD_URL'),
    ('MIKRO_LICENCE_URL', 'CUSTOM_LICENCE_URL'),
    ('MIKRO_RENEW_URL', 'CUSTOM_RENEW_URL')
]
for old_env, new_env in urls:
    old_val = os.environ.get(old_env)
    new_val = os.environ.get(new_env)
    if old_val and new_val:
        old_b = old_val.encode()
        new_b = new_val.encode()
        if len(new_b) <= len(old_b):
            new_b = new_b.ljust(len(old_b), b'\x00')
            if old_b in data:
                data = data.replace(old_b, new_b)
                print(f"✅ 成功替换 URL: {old_env}")

with open(file_path, "wb") as f:
    f.write(data)
