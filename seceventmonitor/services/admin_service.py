from datetime import UTC, datetime

from seceventmonitor.extensions import db
from seceventmonitor.models import AdminUser


def is_initialized() -> bool:
    return db.session.query(AdminUser.id).limit(1).first() is not None


def get_admin_by_id(admin_id: int | None):
    if not admin_id:
        return None
    return db.session.get(AdminUser, admin_id)


def initialize_admin(username: str, password: str):
    username = (username or "").strip()
    password = password or ""

    if is_initialized():
        raise ValueError("系统已初始化，不能重复创建管理员")
    if not username:
        raise ValueError("管理员账号不能为空")
    if len(password) < 6:
        raise ValueError("管理员密码长度不能少于 6 位")

    admin = AdminUser(username=username)
    admin.set_password(password)
    admin.last_login_at = datetime.now(UTC).replace(tzinfo=None)
    db.session.add(admin)
    db.session.commit()
    return admin


def authenticate_admin(username: str, password: str):
    username = (username or "").strip()
    password = password or ""

    admin = AdminUser.query.filter_by(username=username).first()
    if not admin or not admin.check_password(password):
        raise ValueError("账号或密码错误")
    if not admin.is_active:
        raise ValueError("管理员账号已停用")

    admin.mark_login()
    db.session.commit()
    return admin


def update_admin_credentials(
    admin_id: int,
    *,
    username: str,
    current_password: str,
    new_password: str = "",
):
    admin = db.session.get(AdminUser, admin_id)
    if admin is None:
        raise ValueError("管理员不存在")

    username = (username or "").strip()
    current_password = current_password or ""
    new_password = new_password or ""

    if not username:
        raise ValueError("管理员账号不能为空")
    if not current_password:
        raise ValueError("请输入当前密码")
    if not admin.check_password(current_password):
        raise ValueError("当前密码错误")

    existing_admin = AdminUser.query.filter_by(username=username).first()
    if existing_admin is not None and existing_admin.id != admin.id:
        raise ValueError("管理员账号已存在")

    username_changed = admin.username != username
    password_changed = bool(new_password)
    if not username_changed and not password_changed:
        raise ValueError("未检测到需要保存的账号或密码变更")

    admin.username = username
    if password_changed:
        if len(new_password) < 6:
            raise ValueError("新密码长度不能少于 6 位")
        admin.set_password(new_password)

    db.session.commit()
    return admin


def update_admin_username(
    admin_id: int,
    *,
    username: str,
    current_password: str,
):
    return update_admin_credentials(
        admin_id,
        username=username,
        current_password=current_password,
        new_password="",
    )


def update_admin_password(
    admin_id: int,
    *,
    current_password: str,
    new_password: str,
):
    admin = db.session.get(AdminUser, admin_id)
    if admin is None:
        raise ValueError("管理员不存在")
    if not (new_password or "").strip():
        raise ValueError("新密码不能为空")
    return update_admin_credentials(
        admin_id,
        username=admin.username,
        current_password=current_password,
        new_password=new_password,
    )
