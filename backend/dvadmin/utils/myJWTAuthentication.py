from django.conf import settings
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken


class myJWTAuthentication(JWTAuthentication):
    """
    重写校验
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def authenticate(self, request):
        header = self.get_header(request)
        if header is None:
            return None

        raw_token = self.get_raw_token(header)
        if raw_token is None:
            return None

        validated_token = self.get_validated_token(raw_token)
        user = self.get_user(validated_token)
        user_login_flag = user.login_flag
        if settings.STRICT_LOGIN and validated_token['login_flag'] != user_login_flag:
            if user_login_flag == "logout":
                raise InvalidToken({
                    "detail": "Token has invalided",
                    "messages": "token已失效！",
                })
            else:
                raise InvalidToken({
                    "detail": "The user has logged in elsewhere, please confirm the account security!",
                    "code": "User logs in elsewhere",
                    "messages": "用户已在其他地方登录，请确认账户安全！",
                })
        else:
            return user, validated_token
