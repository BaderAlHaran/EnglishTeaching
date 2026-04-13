_open_db = None
_is_postgres = None
_send_email = None
_allowed_file = None
_hash_password = None
_verify_password = None
_email_regex = None
_admin_username = None
_admin_password = None
_admin_email = None
_admin_reset_token = None
_from_email = None
_contact_recipient = None
_upload_folder = None
_logger = None


def configure(
    *,
    open_db,
    is_postgres,
    send_email,
    allowed_file,
    hash_password,
    verify_password,
    email_regex,
    admin_username,
    admin_password,
    admin_email,
    admin_reset_token,
    from_email,
    contact_recipient,
    upload_folder,
    logger,
):
    global _open_db, _is_postgres, _send_email, _allowed_file
    global _hash_password, _verify_password, _email_regex
    global _admin_username, _admin_password, _admin_email, _admin_reset_token
    global _from_email, _contact_recipient, _upload_folder, _logger
    _open_db = open_db
    _is_postgres = is_postgres
    _send_email = send_email
    _allowed_file = allowed_file
    _hash_password = hash_password
    _verify_password = verify_password
    _email_regex = email_regex
    _admin_username = admin_username
    _admin_password = admin_password
    _admin_email = admin_email
    _admin_reset_token = admin_reset_token
    _from_email = from_email
    _contact_recipient = contact_recipient
    _upload_folder = upload_folder
    _logger = logger


def open_db():
    return _open_db()


def is_postgres():
    return _is_postgres()


def send_email(*args, **kwargs):
    return _send_email(*args, **kwargs)


def allowed_file(filename):
    return _allowed_file(filename)


def hash_password(password):
    return _hash_password(password)


def verify_password(password, password_hash):
    return _verify_password(password, password_hash)


def email_regex():
    return _email_regex


def admin_username():
    return _admin_username


def admin_password():
    return _admin_password


def admin_email():
    return _admin_email


def admin_reset_token():
    return _admin_reset_token


def from_email():
    return _from_email


def contact_recipient():
    return _contact_recipient


def upload_folder():
    return _upload_folder


def logger():
    return _logger
