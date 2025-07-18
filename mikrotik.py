from librouteros import connect

MIKROTIK_HOST = '192.168.254.142'
MIKROTIK_USER = 'admin'
MIKROTIK_PASS = 'Deneme123!'
MIKROTIK_PORT = 8728

def mikrotik_login():
    api = connect(
        host=MIKROTIK_HOST,
        username=MIKROTIK_USER,
        password=MIKROTIK_PASS,
        port=MIKROTIK_PORT
    )
    return api

def test_connection():
    api = mikrotik_login()
    system_resource = list(api('/system/resource/print'))[0]
    return system_resource

if __name__ == "__main__":
    print(test_connection())