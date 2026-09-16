"""小米账号认证管理"""
import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import time
from urllib import parse
import aiohttp
from miservice import MiAccount, MiIOService, MiNAService
from miair.config import Config
log = logging.getLogger("miair")
APP_UA = "APP/com.xiaomi.mihome APPV/60209 iosPassportSDK/3.9.0 iOS/17.5.1"

def parse_cookie_string(cookie_str: str) -> dict:
    """解析 cookie 字符串，提取 userId 和 passToken"""
    result = {}
    for item in cookie_str.split(";"):
        item = item.strip()
        if "=" in item:
            key, value = item.split("=", 1)
            key = key.strip()
            value = value.strip()
            if key in ("userId", "passToken"):
                result[key] = value
    return result


class AuthManager:
    """管理小米账号认证和设备服务，新增米家App扫码登录"""
    def __init__(self, config: Config):
        self.config = config
        self.session: aiohttp.ClientSession | None = None
        self.account: MiAccount | None = None
        self.mina_service: MiNAService | None = None
        self.miio_service: MiIOService | None = None
        self._logged_in = False
        self.qr_data = None  # 保存二维码登录临时信息

    async def _gen_qr_login(self):
        """生成米家扫码登录二维码（sid=xiaomiio）"""
        url = "https://account.xiaomi.com/longPolling/loginUrl"
        params = {"sid": "xiaomiio", "_json": "true"}
        headers = {"User-Agent": APP_UA}
        async with self.session.get(url, params=params, headers=headers) as resp:
            raw = await resp.read()
            txt = raw.decode("utf-8", errors="ignore")
            if txt.startswith("&&&START&&&"):
                txt = txt[11:]
            data = json.loads(txt)
        if data.get("code") != 0:
            raise Exception(f"生成二维码失败: {data}")
        return data

    async def _poll_qr_result(self, lp_url: str, timeout: int = 180):
        """长轮询等待米家App扫码确认，返回登录结果"""
        start = time.time()
        headers = {"User-Agent": APP_UA}
        while time.time() - start < timeout:
            try:
                async with self.session.get(lp_url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as r:
                    raw = await r.read()
                    txt = raw.decode("utf-8", errors="ignore")
                    if txt.startswith("&&&START&&&"):
                        txt = txt[11:]
                    res = json.loads(txt)
                code = res.get("code")
                if code == 0:
                    # 扫码确认成功，返回location、userId、passToken、ssecurity
                    return res
                elif code == 86001:
                    # 等待扫码，继续轮询
                    await asyncio.sleep(2)
                    continue
                elif code in (86002, 86003):
                    raise Exception("二维码已过期/已取消，请重新生成二维码")
                else:
                    raise Exception(f"二维码轮询错误 code={code}, {res}")
            except asyncio.TimeoutError:
                # 长轮询正常超时，继续拉取
                continue
        raise Exception("二维码登录超时，3分钟内未完成扫码确认")

    async def login(self):
        """登录小米账号并初始化服务【新增扫码登录分支】"""
        os.makedirs(self.config.conf_path, exist_ok=True)
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=15, connect=5, sock_read=10)
            )
        token_store = self.config.mi_token_home
        token_data = {}
        # ========== 新增：扫码登录分支判断，你需要在config增加一个开关 config.use_qr_login ==========
        if getattr(self.config, "use_qr_login", False):
            log.info("==== 进入米家App扫码登录流程 ====")
            qr_info = await self._gen_qr_login()
            self.qr_data = qr_info
            qr_img_url = qr_info["qr"]
            lp_url = qr_info["lp"]
            log.info(f"请打开米家APP → 我的 → 右上角扫一扫，扫描二维码：{qr_img_url}")
            # 等待扫码确认
            qr_result = await self._poll_qr_result(lp_url)
            log.info("✅ 扫码确认成功！正在提取账号凭据")
            # 从扫码结果拿到userId、passToken
            uid = qr_result["userId"]
            ptk = qr_result["passToken"]
            # 后续鉴权逻辑完全复用原有passToken换取serviceToken代码，下面直接复用
        elif self.config.cookie:
            # 原有cookie解析逻辑不变
            token_data = parse_cookie_string(self.config.cookie)
            uid = token_data.get("userId")
            ptk = token_data.get("passToken")
        else:
            # 账号密码登录分支不变
            uid = None
            ptk = None

        # ---------------- 下面原有逻辑完全不变，不需要改动 ----------------
        if uid and ptk:
            self.account = MiAccount(
                self.session,
                "",
                "",
                token_store=token_store,
            )
            self.account.now_ua = APP_UA
            cached = self.account.token_store.load_token() if self.account.token_store else None
            if (
                cached
                and str(cached.get("userId")) == str(uid)
                and cached.get("passToken") == ptk
                and "micoapi" in cached
            ):
                self.account.token = cached
                self._logged_in = True
                log.info("使用本地缓存的 micoapi serviceToken 登录成功")
            else:
                dev_id = hashlib.md5(f"miair_{uid}".encode()).hexdigest()[:16].upper()
                headers = {"User-Agent": APP_UA}
                cookies = {
                    "sdkVersion": "3.9",
                    "deviceId": dev_id,
                    "userId": str(uid),
                    "passToken": str(ptk),
                }
                url = "https://account.xiaomi.com/pass/serviceLogin?sid=micoapi&_json=true"
                try:
                    async with self.session.get(url, cookies=cookies, headers=headers) as r:
                        raw = await r.read()
                        text = raw.decode("utf-8", errors="ignore")
                        if text.startswith("&&&START&&&"):
                            text = text[11:]
                        resp = json.loads(text)
                    if resp.get("code") == 0:
                        location = resp["location"]
                        nonce = resp["nonce"]
                        ssecurity = resp["ssecurity"]
                        nsec = f"nonce={nonce}&{ssecurity}"
                        client_sign = base64.b64encode(hashlib.sha1(nsec.encode()).digest()).decode()
                        async with self.session.get(location + "&clientSign=" + parse.quote(client_sign)) as r2:
                            service_token_cookie = r2.cookies.get("serviceToken")
                            if service_token_cookie:
                                service_token = service_token_cookie.value
                            else:
                                raise Exception("未在鉴权响应中提取到 serviceToken")
                        self.account.token = {
                            "userId": str(uid),
                            "passToken": str(ptk),
                            "deviceId": dev_id,
                            "ssecurity": ssecurity,
                            "serviceToken": service_token,
                            "micoapi": (ssecurity, service_token),
                        }
                        if self.account.token_store:
                            self.account.token_store.save_token(self.account.token)
                        self._logged_in = True
                        log.info("使用 passToken 成功换取 micoapi serviceToken 并持久化缓存")
                    else:
                        self._logged_in = False
                        code = resp.get("code")
                        desc = resp.get("description") or resp.get("desc", "")
                        log.error(f"passToken 换取小米 serviceToken 失败 (code {code}): {desc}")
                except Exception as e:
                    self._logged_in = False
                    log.error(f"通过 Cookie/passToken 换取小米凭据异常: {e}")
        else:
            # 原有账号密码登录逻辑，原样保留
            self.account = MiAccount(
                self.session,
                self.config.account,
                self.config.password,
                token_store=token_store,
            )
            self.account.now_ua = APP_UA
            if not hasattr(self.account, 'token') or self.account.token is None:
                self.account.token = {"deviceId": hashlib.md5(b"miair").hexdigest()[:16].upper()}
            try:
                await self.account.login("micoapi")
                self._logged_in = True
                log.info("小米账号登录成功")
            except Exception as e:
                self._logged_in = False
                if not hasattr(self.account, 'token') or self.account.token is None:
                    self.account.token = {"deviceId": hashlib.md5(b"miair").hexdigest()[:16].upper()}
                err_msg = str(e)
                err_code = self._extract_error_code(err_msg)
                if err_code == "87001" or "captcha" in err_msg.lower():
                    log.error(
                        "登录需要验证码! 请在浏览器访问 https://account.xiaomi.com 完成验证后重试，"
                        "或使用 cookie 方式登录"
                    )
                elif err_code == "70016":
                    log.error(
                        "登录验证失败! 可能原因：密码错误、需要关闭二次验证、"
                        "或需要在 https://www.mi.com 完成人机验证。"
                        "建议使用 cookie 方式登录。"
                    )
                elif "userId" in err_msg:
                    log.error(
                        "登录失败(缺少userId)! 小米账号可能需要额外验证。"
                        "请尝试以下方法：\n"
                        "  1. 在浏览器登录 https://account.xiaomi.com 完成验证\n"
                        "  2. 使用 cookie 方式登录（在设置中填入 cookie）\n"
                        "  3. 确保关闭了代理/VPN"
                    )
                else:
                    log.error(f"登录失败: {e}")
                if self.config.auto_restart:
                    log.warning("检测到登录失败，正在尝试自动重启程序以恢复服务...")
                    from miair.web.api import _restart_process
                    try:
                        loop = asyncio.get_running_loop()
                        loop.call_later(5, _restart_process)
                    except RuntimeError:
                        _restart_process()
        # 无论是否登录成功，都设置 service
        self.mina_service = MiNAService(self.account)
        self.miio_service = MiIOService(self.account)

    async def ensure_login(self):
        """确保已登录，未登录则尝试登录"""
        if self.mina_service is None or not self._logged_in:
            await self.login()

    @staticmethod
    def _extract_error_code(err_msg: str) -> str:
        """从异常消息中提取数字错误码"""
        m = re.search(r'\b(\d{4,6})\b', err_msg)
        return m.group(1) if m else ""

    async def get_device_list(self) -> list[dict]:
        """获取账号下所有设备列表"""
        await self.ensure_login()
        if not self._logged_in:
            log.warning("未成功登录，无法获取设备列表")
            return []
        try:
            if self.account:
                self.account.now_ua = APP_UA
            devices = await self.mina_service.device_list()
            return devices or []
        except Exception as e:
            log.warning(f"获取设备列表失败: {e}")
            if self.config.cookie:
                log.error(f"Cookie 可能已过期或失效: {e}")
                return []
            await self.close()
            await self.login()
            if not self._logged_in:
                return []
            try:
                devices = await self.mina_service.device_list()
                return devices or []
            except Exception as e2:
                log.error(f"重新登录后仍然失败: {e2}")
                return []

    async def update_speakers_info(self):
        """从云端获取设备信息，更新 speakers 配置"""
        devices = await self.get_device_list()
        did_list = self.config.get_did_list()
        for device in devices:
            miot_did = device.get("miotDID", "")
            if miot_did in did_list:
                speaker = self.config.get_speaker(miot_did)
                speaker.device_id = device.get("deviceID", "")
                speaker.hardware = device.get("hardware", "")
                if not speaker.name:
                    speaker.name = device.get("name", "")
                speaker.ensure_udn()
                log.info(
                    f"已更新设备信息: {speaker.name} "
                    f"(did={miot_did}, device_id={speaker.device_id}, "
                    f"hardware={speaker.hardware})"
                )

    def is_logged_in(self) -> bool:
        """是否已成功登录"""
        return self._logged_in

    async def close(self):
        """关闭 session"""
        if self.session and not self.session.closed:
            await self.session.close()
        self.session = None
        self.account = None
        self.mina_service = None
        self.miio_service = None
        self._logged_in = False
