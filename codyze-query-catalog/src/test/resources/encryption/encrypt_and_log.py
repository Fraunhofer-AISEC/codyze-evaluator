import logging

def encrypt_and_log(data):
    logger = logging.getLogger("mylogger")

    key = get_secret_from_keyserver("encryption_key")
    encrypted_data = encrypt(data, key)
    logger.info("Data encrypted successfully with key: %s", key)

