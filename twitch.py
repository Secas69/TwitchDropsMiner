from __future__ import annotations

import json
import asyncio
import logging
from time import time, monotonic
from copy import deepcopy
from itertools import chain
from functools import partial
from collections import abc, deque, OrderedDict
from datetime import datetime, timedelta, timezone
from contextlib import suppress, asynccontextmanager
from typing import Any, Literal, Final, NoReturn, overload, cast, TYPE_CHECKING

import aiohttp
from yarl import URL

from translate import _
from gui import GUIManager
from channel import Channel
from websocket import WebsocketPool
from inventory import DropsCampaign
from exceptions import (
    ExitRequest,
    GQLException,
    ReloadRequest,
    LoginException,
    MinerException,
    RequestInvalid,
    CaptchaRequired,
    RequestException,
)
from utils import (
    CHARS_HEX_LOWER,
    chunk,
    timestamp,
    create_nonce,
    task_wrapper,
    json_load,
    json_save,
    RateLimiter,
    AwaitableValue,
    ExponentialBackoff,
    Game,
)
from constants import (
    CALL,
    MAX_INT,
    DUMP_PATH,
    COOKIES_PATH,
    MAX_CHANNELS,
    NO_ACL_CHANNEL_COUNT,
    GQL_QUERIES,
    WATCH_INTERVAL,
    RESCAN_COOLDOWN,
    State,
    ClientType,
    PriorityMode,
    WebsocketTopic,
    CLIENT_TYPE_ORDER,
    DEFAULT_CLIENT_TYPE,
    DROPS_GAMES_PATH,
    DISCOVERY_SCAN_SORTS,
    DISCOVERY_SCAN_PAGES,
    DISCOVERY_CACHE_MINUTES,
    DISCOVERY_REMEMBER_DAYS,
    DISCOVERY_REMEMBERED_MAX,
    DISCOVERY_CHANNELS_PER_GAME,
)

if TYPE_CHECKING:
    from gui import LoginForm
    from channel import Stream
    from settings import Settings
    from inventory import TimedDrop
    from constants import ClientInfo, JsonType, GQLOperation


logger = logging.getLogger("TwitchDrops")
gql_logger = logging.getLogger("TwitchDrops.gql")


class SkipExtraJsonDecoder(json.JSONDecoder):
    def decode(self, s: str, *args):
        # skip whitespace check
        obj, end = self.raw_decode(s)
        return obj


SAFE_LOADS = lambda s: json.loads(s, cls=SkipExtraJsonDecoder)


class _AuthState:
    def __init__(self, twitch: Twitch):
        self._twitch: Twitch = twitch
        self._lock = asyncio.Lock()
        self._logged_in = asyncio.Event()
        self.user_id: int
        self.device_id: str
        self.session_id: str
        self.access_token: str
        self.client_version: str
        # the site the device ID was obtained from
        self._device_id_host: str | None = None

    def _hasattrs(self, *attrs: str) -> bool:
        return all(hasattr(self, attr) for attr in attrs)

    def _delattrs(self, *attrs: str) -> None:
        for attr in attrs:
            if hasattr(self, attr):
                delattr(self, attr)

    def invalidate(self, *, delete_cookies: bool = False) -> None:
        self._delattrs("access_token", "user_id")
        self._logged_in.clear()
        self._twitch.gui.help._invalidate_button.config(state="disabled")
        if delete_cookies:
            session = self._twitch._session
            if session is not None:
                jar = cast(aiohttp.CookieJar, session.cookie_jar)
                jar.clear()
                COOKIES_PATH.unlink(missing_ok=True)

    def clear(self) -> None:
        self._delattrs(
            "user_id",
            "device_id",
            "session_id",
            "access_token",
            "client_version",
        )
        self._logged_in.clear()
        self._twitch.gui.help._invalidate_button.config(state="disabled")

    def _login_headers(self, client_info: ClientInfo) -> JsonType:
        return {
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "Accept-Language": "en-US",
            "Cache-Control": "no-cache",
            "Client-Id": client_info.CLIENT_ID,
            "Host": "id.twitch.tv",
            "Origin": str(client_info.CLIENT_URL),
            "Pragma": "no-cache",
            "Referer": str(client_info.CLIENT_URL),
            "User-Agent": client_info.USER_AGENT,
            "X-Device-Id": self.device_id,
        }

    async def _request_device_code(self) -> JsonType:
        """
        Starts the device code login, trying every known client until Twitch accepts one.

        Twitch answers `{"status": 400, "message": "invalid client"}` for client IDs it has
        retired from this flow (the Android app one, since September 2026). The first
        accepted client becomes the one in use, and is remembered in the settings.
        """
        twitch = self._twitch
        clients: dict[str, ClientInfo] = ClientType.by_name()
        names: list[str] = [twitch.client_type_name]
        names.extend(name for name in CLIENT_TYPE_ORDER if name not in names)
        rejected: list[str] = []
        for name in names:
            client_info: ClientInfo = clients[name]
            async with twitch.request(
                "POST",
                "https://id.twitch.tv/oauth2/device",
                headers=self._login_headers(client_info),
                data={"client_id": client_info.CLIENT_ID, "scopes": ""},  # no scopes needed
            ) as response:
                # {
                #     "device_code": "40 chars [A-Za-z0-9]",
                #     "expires_in": 1800,
                #     "interval": 5,
                #     "user_code": "8 chars [A-Z]",
                #     "verification_uri": "https://www.twitch.tv/activate?device-code=ABCDEFGH"
                # }
                try:
                    response_json: JsonType = await response.json(content_type=None)
                except json.JSONDecodeError:
                    response_json = {}
                status: int = response.status
            if status == 200 and "device_code" in response_json:
                twitch.set_client_type(name)
                return response_json
            reason: str = str(response_json.get("message") or f"HTTP {status}")
            logger.info(f"Login: Twitch rejected the {name} client: {reason}")
            rejected.append(f"{name}: {reason}")
        raise LoginException(
            "Twitch rejected the login for every known client ("
            + "; ".join(rejected)
            + "). The application needs an update."
        )

    async def _oauth_login(self) -> str:
        login_form: LoginForm = self._twitch.gui.login
        while True:
            try:
                now = datetime.now(timezone.utc)
                response_json: JsonType = await self._request_device_code()
                client_info: ClientInfo = self._twitch._client_type
                headers: JsonType = self._login_headers(client_info)
                device_code: str = response_json["device_code"]
                user_code: str = response_json["user_code"]
                interval: int = response_json["interval"]
                verification_uri: URL = URL(response_json["verification_uri"])
                expires_at = now + timedelta(seconds=response_json["expires_in"])

                # Print the code to the user, open them the activate page so they can type it in
                await login_form.ask_enter_code(verification_uri, user_code)

                payload = {
                    "client_id": client_info.CLIENT_ID,
                    "device_code": device_code,
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                }
                while True:
                    # sleep first, not like the user is gonna enter the code *that* fast
                    await asyncio.sleep(interval)
                    async with self._twitch.request(
                        "POST",
                        "https://id.twitch.tv/oauth2/token",
                        headers=headers,
                        data=payload,
                        invalidate_after=expires_at,
                    ) as response:
                        # 200 means success, 400 means the user haven't entered the code yet
                        if response.status != 200:
                            continue
                        response_json = await response.json()
                        # {
                        #     "access_token": "40 chars [A-Za-z0-9]",
                        #     "refresh_token": "40 chars [A-Za-z0-9]",
                        #     "scope": [...],
                        #     "token_type": "bearer"
                        # }
                        self.access_token = cast(str, response_json["access_token"])
                        return self.access_token
            except RequestInvalid:
                # the device_code has expired, request a new code
                continue

    async def _login(self) -> str:
        logger.info("Login flow started")
        gui_print = self._twitch.gui.print
        login_form: LoginForm = self._twitch.gui.login
        client_info: ClientInfo = self._twitch._client_type

        token_kind: str = ''
        use_chrome: bool = False
        payload: JsonType = {
            # username and password are added later
            # "username": str,
            # "password": str,
            # client ID to-be associated with the access token
            "client_id": client_info.CLIENT_ID,
            "undelete_user": False,  # purpose unknown
            "remember_me": True,  # persist the session via the cookie
            # "authy_token": str,  # 2FA token
            # "twitchguard_code": str,  # email code
            # "captcha": str,  # self-fed captcha
            # 'force_twitchguard': False,  # force email code confirmation
        }

        while True:
            login_data = await login_form.ask_login()
            payload["username"] = login_data.username
            payload["password"] = login_data.password
            # reinstate the 2FA token, if present
            payload.pop("authy_token", None)
            payload.pop("twitchguard_code", None)
            if login_data.token:
                # if there's no token kind set yet, and the user has entered a token,
                # we can immediately assume it's an authenticator token and not an email one
                if not token_kind:
                    token_kind = "authy"
                if token_kind == "authy":
                    payload["authy_token"] = login_data.token
                elif token_kind == "email":
                    payload["twitchguard_code"] = login_data.token

            # use fancy headers to mimic the twitch android app
            headers = {
                "Accept": "application/vnd.twitchtv.v3+json",
                "Accept-Encoding": "gzip",
                "Accept-Language": "en-US",
                "Client-Id": client_info.CLIENT_ID,
                "Content-Type": "application/json; charset=UTF-8",
                "Host": "passport.twitch.tv",
                "User-Agent": client_info.USER_AGENT,
                "X-Device-Id": self.device_id,
                # "X-Device-Id": ''.join(random.choices('0123456789abcdef', k=32)),
            }
            async with self._twitch.request(
                "POST", "https://passport.twitch.tv/login", headers=headers, json=payload
            ) as response:
                login_response: JsonType = await response.json(loads=SAFE_LOADS)

            # Feed this back in to avoid running into CAPTCHA if possible
            if "captcha_proof" in login_response:
                payload["captcha"] = {"proof": login_response["captcha_proof"]}

            # Error handling
            if "error_code" in login_response:
                error_code: int = login_response["error_code"]
                logger.info(f"Login error code: {error_code}")
                if error_code == 1000:
                    logger.info("1000: CAPTCHA is required")
                    use_chrome = True
                    break
                elif error_code in (2004, 3001):
                    logger.info("3001: Login failed due to incorrect username or password")
                    gui_print(_("login", "incorrect_login_pass"))
                    if error_code == 2004:
                        # invalid username
                        login_form.clear(login=True)
                    login_form.clear(password=True)
                    continue
                elif error_code in (
                    3012,  # Invalid authy token
                    3023,  # Invalid email code
                ):
                    logger.info("3012/23: Login failed due to incorrect 2FA code")
                    if error_code == 3023:
                        token_kind = "email"
                        gui_print(_("login", "incorrect_email_code"))
                    else:
                        token_kind = "authy"
                        gui_print(_("login", "incorrect_twofa_code"))
                    login_form.clear(token=True)
                    continue
                elif error_code in (
                    3011,  # Authy token needed
                    3022,  # Email code needed
                ):
                    # 2FA handling
                    logger.info("3011/22: 2FA token required")
                    # user didn't provide a token, so ask them for it
                    if error_code == 3022:
                        token_kind = "email"
                        gui_print(_("login", "email_code_required"))
                    else:
                        token_kind = "authy"
                        gui_print(_("login", "twofa_code_required"))
                    continue
                elif error_code >= 5000:
                    # Special errors, usually from Twitch telling the user to "go away"
                    # We print the code out to inform the user, and just use chrome flow instead
                    # {
                    #     "error_code":5023,
                    #     "error":"Please update your app to continue",
                    #     "error_description":"client is not supported for this feature"
                    # }
                    # {
                    #     "error_code":5027,
                    #     "error":"Please update your app to continue",
                    #     "error_description":"client blocked from this operation"
                    # }
                    gui_print(_("login", "error_code").format(error_code=error_code))
                    logger.info(str(login_response))
                    use_chrome = True
                    break
                else:
                    ext_msg = str(login_response)
                    logger.info(ext_msg)
                    raise LoginException(ext_msg)
            # Success handling
            if "access_token" in login_response:
                self.access_token = cast(str, login_response["access_token"])
                logger.info("Access token granted")
                login_form.clear()
                break

        if use_chrome:
            # await self._chrome_login()
            raise CaptchaRequired()

        if hasattr(self, "access_token"):
            return self.access_token
        raise LoginException("Login flow finished without setting the access token")

    def headers(self, *, user_agent: str = '', gql: bool = False) -> JsonType:
        client_info: ClientInfo = self._twitch._client_type
        headers = {
            "Accept": "*/*",
            "Accept-Encoding": "gzip",
            "Accept-Language": "en-US",
            "Pragma": "no-cache",
            "Cache-Control": "no-cache",
            "Client-Id": client_info.CLIENT_ID,
        }
        if user_agent:
            headers["User-Agent"] = user_agent
        if hasattr(self, "session_id"):
            headers["Client-Session-Id"] = self.session_id
        # if hasattr(self, "client_version"):
            # headers["Client-Version"] = self.client_version
        if hasattr(self, "device_id"):
            headers["X-Device-Id"] = self.device_id
        if gql:
            headers["Origin"] = str(client_info.CLIENT_URL)
            headers["Referer"] = str(client_info.CLIENT_URL)
            headers["Authorization"] = f"OAuth {self.access_token}"
        return headers

    async def _fetch_device_id(self, jar: aiohttp.CookieJar) -> None:
        client_url: URL = self._twitch._client_type.CLIENT_URL
        async with self._twitch.request("GET", client_url, headers=self.headers()) as response:
            page_html = await response.text("utf8")
            assert page_html is not None
        # doing the request ends up setting the "unique_id" value in the cookie
        cookie = jar.filter_cookies(client_url)
        self.device_id = cookie["unique_id"].value

    def _saved_token(self, jar: aiohttp.CookieJar) -> tuple[str, str] | None:
        """
        Finds an auth token saved in the cookies, checking the current client's site first.

        Returns the token and the host it was saved for.
        """
        urls: list[URL] = [self._twitch._client_type.CLIENT_URL]
        for info in ClientType.by_name().values():
            if info.CLIENT_URL not in urls:
                urls.append(info.CLIENT_URL)
        for url in urls:
            cookie = jar.filter_cookies(url)
            if "auth-token" in cookie and cookie["auth-token"].value and url.host:
                return cookie["auth-token"].value, url.host
        return None

    async def _validate_token(self, token: str) -> JsonType | None:
        """
        Returns Twitch's details about the token (user ID, client ID), or None if invalid.
        """
        for attempt in range(3):
            async with self._twitch.request(
                "GET",
                "https://id.twitch.tv/oauth2/validate",
                headers={"Authorization": f"OAuth {token}"},
            ) as response:
                if response.status == 401:
                    return None
                elif response.status == 200:
                    return cast("JsonType", await response.json())
                logger.info(f"Token validation returned HTTP {response.status}")
        raise RuntimeError("Login verification failure: unexpected validation response")

    async def validate(self):
        async with self._lock:
            await self._validate()

    async def _validate(self):
        if not hasattr(self, "session_id"):
            self.session_id = create_nonce(CHARS_HEX_LOWER, 16)
        if not self._hasattrs("device_id", "access_token", "user_id"):
            session = await self._twitch.get_session()
            jar = cast(aiohttp.CookieJar, session.cookie_jar)
        if not self._hasattrs("device_id"):
            await self._fetch_device_id(jar)
            self._device_id_host = self._twitch._client_type.CLIENT_URL.host
        if not self._hasattrs("access_token", "user_id"):
            # looks like we're missing something
            login_form: LoginForm = self._twitch.gui.login
            logger.info("Checking login")
            login_form.update(_("gui", "login", "logging_in"), None)
            validate_response: JsonType | None = None
            for attempt in range(3):
                saved_host: str | None = None
                if hasattr(self, "access_token"):
                    pass
                elif (saved := self._saved_token(jar)) is not None:
                    logger.info("Restoring session from cookie")
                    self.access_token, saved_host = saved
                else:
                    self.access_token = await self._oauth_login()
                validate_response = await self._validate_token(self.access_token)
                if validate_response is None:
                    # the access token we have is invalid - forget it and login again
                    logger.info("Restored session is invalid")
                    self._delattrs("access_token")
                    if saved_host is not None:
                        jar.clear_domain(saved_host)
                    continue
                # use the client the token was issued for - an older login made with a
                # client Twitch doesn't accept for new logins anymore can still be valid
                client_id: str = validate_response["client_id"]
                for name, info in ClientType.by_name().items():
                    if info.CLIENT_ID == client_id:
                        self._twitch.set_client_type(name)
                        if info.CLIENT_URL.host != self._device_id_host:
                            # the device ID cookie is per site, get the one of the new client
                            await self._fetch_device_id(jar)
                            self._device_id_host = info.CLIENT_URL.host
                        break
                else:
                    # a token of a client we don't know - start over from scratch
                    logger.info("Cookie client ID mismatch")
                    self._delattrs("access_token")
                    jar.clear()
                    COOKIES_PATH.unlink(missing_ok=True)
                    validate_response = None
                    continue
                break
            if validate_response is None:
                raise RuntimeError("Login verification failure")
            self.user_id = int(validate_response["user_id"])
            client_url: URL = self._twitch._client_type.CLIENT_URL
            cookie = jar.filter_cookies(client_url)
            cookie["auth-token"] = self.access_token
            cookie["persistent"] = str(self.user_id)
            logger.info(f"Login successful, user ID: {self.user_id}")
            login_form.update(_("gui", "login", "logged_in"), self.user_id)
            # update our cookie and save it
            jar.update_cookies(cookie, client_url)
            jar.save(COOKIES_PATH)
        self._twitch.gui.help._invalidate_button.config(state="normal")
        self._logged_in.set()


class Twitch:
    def __init__(self, settings: Settings):
        self.settings: Settings = settings
        # State management
        self._state: State = State.IDLE
        self._state_change = asyncio.Event()
        self.wanted_games: list[Game] = []
        self.inventory: list[DropsCampaign] = []
        self._drops: dict[str, TimedDrop] = {}
        self._campaigns: dict[str, DropsCampaign] = {}
        self._mnt_triggers: deque[datetime] = deque()
        # Targeted re-scans for "Allowed Channels: All" games whose last channel is gone:
        self._pending_rescans: set[Game] = set()  # waiting until the game becomes actively mined
        self._rescan_now: Game | None = None  # one-shot order, processed by CHANNEL_SWITCH
        self._rescan_last: dict[Game, float] = {}  # monotonic time of the last attempt
        # NOTE: GQL is pretty volatile and breaks everything if one runs into their rate limit.
        # Do not modify the default, safe values.
        self._qgl_limiter = RateLimiter(capacity=5, window=1)
        # Client type, session and auth
        # NOTE: The client is a setting, because Twitch retires client IDs from time to time
        clients: dict[str, ClientInfo] = ClientType.by_name()
        self.client_type_name: str = settings.client_type
        if self.client_type_name not in clients:
            logger.warning(f"Unknown client type in the settings: {self.client_type_name!r}")
            self.client_type_name = DEFAULT_CLIENT_TYPE
        self._client_type: ClientInfo = clients[self.client_type_name]
        self._session: aiohttp.ClientSession | None = None
        self._auth_state: _AuthState = _AuthState(self)
        # GUI
        self.gui = GUIManager(self)
        # Storing and watching channels
        self.channels: OrderedDict[int, Channel] = OrderedDict()
        self.watching_channel: AwaitableValue[Channel] = AwaitableValue()
        self._watching_task: asyncio.Task[None] | None = None
        self._watching_restart = asyncio.Event()
        # Websocket
        self.websocket = WebsocketPool(self)
        # Maintenance task
        self._mnt_task: asyncio.Task[None] | None = None
        # Campaign discovery results: (timestamp, campaigns data)
        self._discovery_cache: tuple[float, dict[str, JsonType]] | None = None

    def set_client_type(self, name: str) -> None:
        """
        Switches the Twitch client used for logging in and API requests.

        The choice is saved in the settings, so the next run starts with a working client.
        """
        if name == self.client_type_name:
            return
        logger.info(f"Switching the Twitch client: {self.client_type_name} -> {name}")
        self.client_type_name = name
        self._client_type = ClientType.by_name()[name]
        if self._session is not None:
            self._session.headers["User-Agent"] = self._client_type.USER_AGENT
        self.settings.client_type = name
        self.settings.save()

    async def get_session(self) -> aiohttp.ClientSession:
        if (session := self._session) is not None:
            if session.closed:
                raise RuntimeError("Session is closed")
            return session
        # load in cookies
        cookie_jar = aiohttp.CookieJar()
        try:
            if COOKIES_PATH.exists():
                cookie_jar.load(COOKIES_PATH)
        except Exception:
            # if loading in the cookies file ends up in an error, just ignore it
            # clear the jar, just in case
            cookie_jar.clear()
        # create timeouts
        # connection quality mulitiplier determines the magnitude of timeouts
        connection_quality = self.settings.connection_quality
        if connection_quality < 1:
            connection_quality = self.settings.connection_quality = 1
        elif connection_quality > 6:
            connection_quality = self.settings.connection_quality = 6
        timeout = aiohttp.ClientTimeout(
            sock_connect=5*connection_quality,
            total=10*connection_quality,
        )
        # create session, limited to 50 connections at maximum
        connector = aiohttp.TCPConnector(limit=50)
        self._session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            cookie_jar=cookie_jar,
            headers={"User-Agent": self._client_type.USER_AGENT},
        )
        return self._session

    async def shutdown(self) -> None:
        start_time = time()
        self.stop_watching()
        if self._watching_task is not None:
            self._watching_task.cancel()
            self._watching_task = None
        if self._mnt_task is not None:
            self._mnt_task.cancel()
            self._mnt_task = None
        # stop websocket, close session and save cookies
        await self.websocket.stop(clear_topics=True)
        if self._session is not None:
            cookie_jar = cast(aiohttp.CookieJar, self._session.cookie_jar)
            # clear empty cookie entries off the cookies file before saving
            # NOTE: Unfortunately, aiohttp provides no easy way of clearing empty cookies,
            # so we need to access the private '_cookies' attribute for this.
            for cookie_key, cookie in list(cookie_jar._cookies.items()):
                if not cookie:
                    del cookie_jar._cookies[cookie_key]
            cookie_jar.save(COOKIES_PATH)
            await self._session.close()
            self._session = None
        self._drops.clear()
        self.channels.clear()
        self.inventory.clear()
        self._auth_state.clear()
        self.wanted_games.clear()
        self._mnt_triggers.clear()
        self._pending_rescans.clear()
        self._rescan_now = None
        self._rescan_last.clear()
        # wait at least half a second + whatever it takes to complete the closing
        # this allows aiohttp to safely close the session
        await asyncio.sleep(start_time + 0.5 - time())

    def wait_until_login(self) -> abc.Coroutine[Any, Any, Literal[True]]:
        return self._auth_state._logged_in.wait()

    def change_state(self, state: State) -> None:
        if self._state is not State.EXIT:
            # prevent state changing once we switch to exit state
            self._state = state
        self._state_change.set()

    def state_change(self, state: State) -> abc.Callable[[], None]:
        # this is identical to change_state, but defers the call
        # perfect for GUI usage
        return partial(self.change_state, state)

    def close(self):
        """
        Called when the application is requested to close by the user,
        usually by the console or application window being closed.
        """
        self.change_state(State.EXIT)

    def prevent_close(self):
        """
        Called when the application window has to be prevented from closing, even after the user
        closes it with X. Usually used solely to display tracebacks from the closing sequence.
        """
        self.gui.prevent_close()

    def print(self, message: str):
        """
        Can be used to print messages within the GUI.
        """
        self.gui.print(message)

    def save(self, *, force: bool = False) -> None:
        """
        Saves the application state.
        """
        self.gui.save(force=force)
        self.settings.save(force=force)

    def get_priority(self, channel: Channel) -> int:
        """
        Return a priority number for a given channel.

        0 has the highest priority.
        Higher numbers -> lower priority.
        MAX_INT (a really big number) signifies the lowest possible priority.
        """
        if (
            (game := channel.game) is None  # None when OFFLINE or no game set
            or game not in self.wanted_games  # we don't care about the played game
        ):
            return MAX_INT
        return self.wanted_games.index(game)

    @staticmethod
    def _viewers_key(channel: Channel) -> int:
        if (viewers := channel.viewers) is not None:
            return viewers
        return -1

    async def run(self):
        if self.settings.dump:
            with open(DUMP_PATH, 'w', encoding="utf8"):
                # replace the existing file with an empty one
                pass
        while True:
            try:
                await self._run()
                break
            except ReloadRequest:
                await self.shutdown()
            except ExitRequest:
                break
            except aiohttp.ContentTypeError as exc:
                raise RequestException(_("login", "unexpected_content")) from exc

    async def _run(self):
        """
        Main method that runs the whole client.

        Here, we manage several things, specifically:
        • Fetching the drops inventory to make sure that everything we can claim, is claimed
        • Selecting a stream to watch, and watching it
        • Changing the stream that's being watched if necessary
        """
        self.gui.start()
        auth_state = await self.get_auth()
        await self.websocket.start()
        # NOTE: watch task is explicitly restarted on each new run
        if self._watching_task is not None:
            self._watching_task.cancel()
        self._watching_task = asyncio.create_task(self._watch_loop())
        # Add default topics
        self.websocket.add_topics([
            WebsocketTopic("User", "Drops", auth_state.user_id, self.process_drops),
            WebsocketTopic(
                "User", "Notifications", auth_state.user_id, self.process_notifications
            ),
        ])
        full_cleanup: bool = False
        channels: Final[OrderedDict[int, Channel]] = self.channels
        self.change_state(State.INVENTORY_FETCH)
        while True:
            if self._state is State.IDLE:
                if self.settings.dump:
                    self.gui.close()
                    continue
                self.gui.tray.change_icon("idle")
                self.gui.status.update(_("gui", "status", "idle"))
                self.stop_watching()
                # clear the flag and wait until it's set again
                self._state_change.clear()
            elif self._state is State.INVENTORY_FETCH:
                self.gui.tray.change_icon("maint")
                # ensure the websocket is running
                await self.websocket.start()
                await self.fetch_inventory()
                self.gui.set_games(set(campaign.game for campaign in self.inventory))
                # Save state on every inventory fetch
                self.save()
                self.change_state(State.GAMES_UPDATE)
            elif self._state is State.GAMES_UPDATE:
                # claim drops from expired and active campaigns
                for campaign in self.inventory:
                    if not campaign.upcoming:
                        for drop in campaign.drops:
                            if drop.can_claim:
                                await drop.claim()
                # figure out which games we want
                self.wanted_games.clear()
                exclude = self.settings.exclude
                priority = self.settings.priority
                priority_mode = self.settings.priority_mode
                priority_only = priority_mode is PriorityMode.PRIORITY_ONLY
                next_hour = datetime.now(timezone.utc) + timedelta(hours=1)
                # sorted_campaigns: list[DropsCampaign] = list(self.inventory)
                sorted_campaigns: list[DropsCampaign] = self.inventory
                if not priority_only:
                    if priority_mode is PriorityMode.ENDING_SOONEST:
                        sorted_campaigns.sort(key=lambda c: c.ends_at)
                    elif priority_mode is PriorityMode.LOW_AVBL_FIRST:
                        sorted_campaigns.sort(key=lambda c: c.availability)
                sorted_campaigns.sort(
                    key=lambda c: (
                        priority.index(c.game.name) if c.game.name in priority else MAX_INT
                    )
                )
                for campaign in sorted_campaigns:
                    game: Game = campaign.game
                    if (
                        game not in self.wanted_games  # isn't already there
                        # and isn't excluded by list or priority mode
                        and game.name not in exclude
                        and (not priority_only or game.name in priority)
                        # and can be progressed within the next hour
                        and campaign.can_earn_within(next_hour)
                    ):
                        # non-excluded games with no priority are placed last, below priority ones
                        self.wanted_games.append(game)
                # drop re-scans of games that aren't wanted anymore
                self._pending_rescans.intersection_update(self.wanted_games)
                if self._rescan_now is not None and self._rescan_now not in self.wanted_games:
                    self._rescan_now = None
                for game in list(self._rescan_last):
                    if game not in self.wanted_games:
                        del self._rescan_last[game]
                full_cleanup = True
                self.restart_watching()
                self.change_state(State.CHANNELS_CLEANUP)
            elif self._state is State.CHANNELS_CLEANUP:
                self.gui.status.update(_("gui", "status", "cleanup"))
                if not self.wanted_games or full_cleanup:
                    # no games selected or we're doing full cleanup: remove everything
                    to_remove_channels: list[Channel] = list(channels.values())
                else:
                    # remove all channels that:
                    to_remove_channels = [
                        channel
                        for channel in channels.values()
                        if (
                            not channel.acl_based  # aren't ACL-based
                            and (
                                channel.offline  # and are offline
                                # or online but aren't streaming the game we want anymore
                                or (channel.game is None or channel.game not in self.wanted_games)
                            )
                        )
                    ]
                full_cleanup = False
                if to_remove_channels:
                    to_remove_topics: list[str] = []
                    for channel in to_remove_channels:
                        to_remove_topics.append(
                            WebsocketTopic.as_str("Channel", "StreamState", channel.id)
                        )
                        to_remove_topics.append(
                            WebsocketTopic.as_str("Channel", "StreamUpdate", channel.id)
                        )
                    self.websocket.remove_topics(to_remove_topics)
                    for channel in to_remove_channels:
                        del channels[channel.id]
                        channel.remove()
                    del to_remove_channels, to_remove_topics
                if self.wanted_games:
                    self.change_state(State.CHANNELS_FETCH)
                else:
                    # with no games available, we switch to IDLE after cleanup
                    self.print(_("status", "no_campaign"))
                    self.change_state(State.IDLE)
            elif self._state is State.CHANNELS_FETCH:
                self.gui.status.update(_("gui", "status", "gathering"))
                # a full scan covers every game, so pending targeted re-scans are redundant
                self._pending_rescans.clear()
                self._rescan_now = None
                # start with all current channels, clear the memory and GUI
                new_channels: set[Channel] = set(channels.values())
                channels.clear()
                self.gui.channels.clear()
                # gather and add ACL channels from campaigns
                # NOTE: we consider only campaigns that can be progressed
                # NOTE: we use another set so that we can set them online separately
                no_acl: set[Game] = set()
                acl_channels: set[Channel] = set()
                next_hour = datetime.now(timezone.utc) + timedelta(hours=1)
                for campaign in self.inventory:
                    if (
                        campaign.game in self.wanted_games
                        and campaign.can_earn_within(next_hour)
                    ):
                        if campaign.allowed_channels:
                            acl_channels.update(campaign.allowed_channels)
                        else:
                            no_acl.add(campaign.game)
                # remove all ACL channels that already exist from the other set
                acl_channels.difference_update(new_channels)
                # use the other set to set them online if possible
                await self.bulk_check_online(acl_channels)
                # finally, add them as new channels
                new_channels.update(acl_channels)
                for game in no_acl:
                    # for every campaign without an ACL, for it's game,
                    # only track the top live channels by viewers; the drops are
                    # assumed to be mineable as long as the channel stays online
                    # and keeps streaming the game
                    game_channels = await self.get_live_streams(
                        game, limit=NO_ACL_CHANNEL_COUNT, drops_enabled=True,
                        sort="VIEWER_COUNT",
                    )
                    new_channels.update(game_channels)
                # sort them descending by viewers, by priority and by game priority
                # NOTE: Viewers sort also ensures ONLINE channels are sorted to the top
                # NOTE: We can drop using the set now, because there's no more channels being added
                ordered_channels: list[Channel] = sorted(
                    new_channels, key=self._viewers_key, reverse=True
                )
                ordered_channels.sort(key=lambda ch: ch.acl_based, reverse=True)
                ordered_channels.sort(key=self.get_priority)
                # ensure that we won't end up with more channels than we can handle
                # NOTE: we trim from the end because that's where the non-priority,
                # offline (or online but low viewers) channels end up
                to_remove_channels = ordered_channels[MAX_CHANNELS:]
                ordered_channels = ordered_channels[:MAX_CHANNELS]
                if to_remove_channels:
                    # tracked channels and gui were cleared earlier, so no need to do it here
                    # just make sure to unsubscribe from their topics
                    to_remove_topics = []
                    for channel in to_remove_channels:
                        to_remove_topics.append(
                            WebsocketTopic.as_str("Channel", "StreamState", channel.id)
                        )
                        to_remove_topics.append(
                            WebsocketTopic.as_str("Channel", "StreamUpdate", channel.id)
                        )
                    self.websocket.remove_topics(to_remove_topics)
                    del to_remove_channels, to_remove_topics
                # set our new channel list
                for channel in ordered_channels:
                    channels[channel.id] = channel
                    channel.display(add=True)
                # subscribe to these channel's state updates
                to_add_topics: list[WebsocketTopic] = []
                for channel_id in channels:
                    to_add_topics.append(
                        WebsocketTopic(
                            "Channel", "StreamState", channel_id, self.process_stream_state
                        )
                    )
                    to_add_topics.append(
                        WebsocketTopic(
                            "Channel", "StreamUpdate", channel_id, self.process_stream_update
                        )
                    )
                self.websocket.add_topics(to_add_topics)
                # relink watching channel after cleanup,
                # or stop watching it if it no longer qualifies
                # NOTE: this replaces 'self.watching_channel's internal value with the new object
                watching_channel = self.watching_channel.get_with_default(None)
                if watching_channel is not None:
                    new_watching: Channel | None = channels.get(watching_channel.id)
                    if new_watching is not None and self.can_watch(new_watching):
                        self.watch(new_watching, update_status=False)
                    else:
                        # we've removed a channel we were watching
                        self.stop_watching()
                    del new_watching
                # pre-display the active drop with a substracted minute
                for channel in channels.values():
                    # check if there's any channels we can watch first
                    if self.can_watch(channel):
                        if (
                            (active_campaign := self.get_active_campaign(channel)) is not None
                            and (active_drop := active_campaign.first_drop) is not None
                        ):
                            active_drop.display(countdown=False, subone=True)
                        break
                self.change_state(State.CHANNEL_SWITCH)
                del (
                    no_acl,
                    acl_channels,
                    new_channels,
                    to_add_topics,
                    ordered_channels,
                    watching_channel,
                )
            elif self._state is State.CHANNEL_SWITCH:
                if self.settings.dump:
                    self.gui.close()
                    continue
                # consume the state change up front, so that a change requested
                # while the re-scan below is in flight isn't swallowed by the clears
                # at the end of this branch
                self._state_change.clear()
                # run a targeted single-game re-scan before picking the next channel,
                # so the fresh channels are already candidates for the switch
                rescan_game, self._rescan_now = self._rescan_now, None
                if rescan_game is not None:
                    await self.rescan_game_channels(rescan_game)
                # a loss noted during the rescan above may have queued another game;
                # give it one chance to run in the same branch (bounded: each run
                # records its own cooldown), but only if we're still in this state
                if self._state is State.CHANNEL_SWITCH:
                    self._promote_pending_rescans()
                    if self._rescan_now is not None:
                        rescan_game, self._rescan_now = self._rescan_now, None
                        await self.rescan_game_channels(rescan_game)
                self.gui.status.update(_("gui", "status", "switching"))
                # Change into the selected channel, stay in the watching channel,
                # or select a new channel that meets the required conditions
                new_watching = None
                selected_channel = self.gui.channels.get_selection()
                if selected_channel is not None and self.can_watch(selected_channel):
                    # selected channel is checked first, and set as long as we can watch it
                    new_watching = selected_channel
                else:
                    # other channels additionally need to have a good reason
                    # for a switch (including the watching one)
                    # NOTE: we need to sort the channels every time because one channel
                    # can end up streaming any game - channels aren't game-tied
                    for channel in sorted(channels.values(), key=self.get_priority):
                        if self.should_switch(channel):
                            new_watching = channel
                            break
                watching_channel = self.watching_channel.get_with_default(None)
                if new_watching is not None:
                    # if we have a better switch target - do so
                    self.watch(new_watching)
                elif watching_channel is not None and self.can_watch(watching_channel):
                    # otherwise, continue watching what we had before
                    self.gui.status.update(
                        _("status", "watching").format(channel=watching_channel.name)
                    )
                else:
                    # not watching anything and there isn't anything to watch either
                    self.print(_("status", "no_channel"))
                    # no other state was requested while we were switching (a
                    # same-state re-scan request leaves _state unchanged, so
                    # checking the pending event covers it too)
                    if (self._state is State.CHANNEL_SWITCH
                            and not self._state_change.is_set()):
                        self.change_state(State.IDLE)
                del new_watching, selected_channel, watching_channel
            elif self._state is State.RESTART:
                raise ReloadRequest()
            elif self._state is State.EXIT:
                self.gui.tray.change_icon("pickaxe")
                self.gui.status.update(_("gui", "status", "exiting"))
                # we've been requested to exit the application
                break
            await self._state_change.wait()

    async def _watch_sleep(self, delay: float) -> None:
        # we use wait_for here to allow an asyncio.sleep-like that can be ended prematurely
        self._watching_restart.clear()
        with suppress(asyncio.TimeoutError):
            await asyncio.wait_for(self._watching_restart.wait(), timeout=delay)

    @task_wrapper(critical=True)
    async def _watch_loop(self) -> NoReturn:
        interval: float = WATCH_INTERVAL.total_seconds()
        while True:
            channel: Channel = await self.watching_channel.get()
            if not channel.online:
                # if the channel isn't online anymore, we stop watching it
                self.stop_watching()
                continue
            # logger.log(CALL, f"Sending watch payload to: {channel.name}")
            last_sent: float = time()
            succeeded: bool = await channel.send_watch()
            if not succeeded:
                logger.log(CALL, f"Watch requested failed for channel: {channel.name}")
            # wait ~15 seconds for a progress update
            await asyncio.sleep(15 - min(time() - last_sent, 15))
            if self.gui.progress.minute_almost_done():
                # If the previous update was more than ~60s ago, and the progress tracker
                # isn't counting down anymore, that means Twitch has temporarily
                # stopped reporting drop's progress. To ensure the timer keeps at least somewhat
                # accurate time, we can use GQL to query for the current drop,
                # or even "pretend" mining as a last resort option.
                handled: bool = False

                # Solution 1: use GQL to query for the currently mined drop status
                try:
                    context = await self.gql_request(
                        GQL_QUERIES["CurrentDrop"].with_variables(
                            {"channelID": str(channel.id)}
                        )
                    )
                    drop_data: JsonType | None = (
                        context["data"]["currentUser"]["dropCurrentSession"]
                    )
                except GQLException:
                    drop_data = None
                if drop_data is not None:
                    gql_drop: TimedDrop | None = self._drops.get(drop_data["dropID"])
                    if gql_drop is not None and gql_drop.can_earn(channel):
                        gql_drop.update_minutes(drop_data["currentMinutesWatched"])
                        drop_text: str = (
                            f"{gql_drop.name} ({gql_drop.campaign.game}, "
                            f"{gql_drop.current_minutes}/{gql_drop.required_minutes})"
                        )
                        logger.log(CALL, f"Drop progress from GQL: {drop_text}")
                        handled = True

                # Solution 2: If GQL fails, figure out which campaign we're most likely mining
                # right now, and then bump up the minutes on it's drops
                if not handled:
                    if (active_campaign := self.get_active_campaign(channel)) is not None:
                        active_campaign.bump_minutes(channel)
                        # NOTE: This usually gets overwritten below
                        drop_text = f"Unknown drop ({active_campaign.game})"
                        if (active_drop := active_campaign.first_drop) is not None:
                            active_drop.display()
                            drop_text = (
                                f"{active_drop.name} ({active_drop.campaign.game}, "
                                f"{active_drop.current_minutes}/{active_drop.required_minutes})"
                            )
                        logger.log(CALL, f"Drop progress from active search: {drop_text}")
                        handled = True
                    else:
                        logger.log(CALL, "No active drop could be determined")
            await self._watch_sleep(interval - min(time() - last_sent, interval))

    @task_wrapper(critical=True)
    async def _maintenance_task(self) -> None:
        now = datetime.now(timezone.utc)
        next_period = now + timedelta(hours=1)
        while True:
            # exit if there's no need to repeat the loop
            now = datetime.now(timezone.utc)
            if now >= next_period:
                break
            next_trigger = next_period
            while self._mnt_triggers and self._mnt_triggers[0] <= next_trigger:
                next_trigger = self._mnt_triggers.popleft()
            trigger_type: str = "Reload" if next_trigger == next_period else "Cleanup"
            logger.log(
                CALL,
                (
                    "Maintenance task waiting until: "
                    f"{next_trigger.astimezone().strftime('%X')} ({trigger_type})"
                )
            )
            await asyncio.sleep((next_trigger - now).total_seconds())
            # exit after waiting, before the actions
            now = datetime.now(timezone.utc)
            if now >= next_period:
                break
            if next_trigger != next_period:
                logger.log(CALL, "Maintenance task requests channels cleanup")
                self.change_state(State.CHANNELS_CLEANUP)
        # this triggers a restart of this task every (up to) 60 minutes
        logger.log(CALL, "Maintenance task requests a reload")
        self.change_state(State.INVENTORY_FETCH)

    def can_watch(self, channel: Channel) -> bool:
        """
        Determines if the given channel qualifies as a watching candidate.
        """
        # exit early if stream is offline
        if not channel.online:
            return False
        for campaign in self.inventory:
            if (
                campaign.can_earn(channel)  # let the campaign do the "special games" check
                and (
                    # limit watching to the games the user wants
                    channel.game is not None
                    and channel.drops_enabled
                    and channel.game in self.wanted_games
                    # let the campaign ignore all channel-related checks
                    or campaign.game.is_special()
                )
            ):
                return True
        return False

    def _is_no_acl_game(self, game: Game) -> bool:
        """
        Whether the game has an active, earnable "Allowed Channels: All" campaign,
        i.e. a campaign without a fixed channel list (same condition as CHANNELS_FETCH).
        """
        next_hour = datetime.now(timezone.utc) + timedelta(hours=1)
        return any(
            campaign.game == game
            and not campaign.allowed_channels
            and campaign.can_earn_within(next_hour)
            for campaign in self.inventory
        )

    def _has_live_game_channel(self, game: Game) -> bool:
        """Whether there's a tracked channel that's online and streaming the game."""
        return any(
            channel.online and channel.game == game and channel.drops_enabled
            for channel in self.channels.values()
        )

    def should_switch(self, channel: Channel) -> bool:
        """
        Determines if the given channel qualifies as a switch candidate.
        """
        if not self.can_watch(channel):
            return False
        watching_channel = self.watching_channel.get_with_default(None)
        if watching_channel is None or not self.can_watch(watching_channel):
            return True
        channel_order = self.get_priority(channel)
        watching_order = self.get_priority(watching_channel)
        return (
            # this channel's game is higher order than the watching one's
            channel_order < watching_order
            or channel_order == watching_order  # or the order is the same
            # and this channel is ACL-based and the watching channel isn't
            and channel.acl_based > watching_channel.acl_based
        )

    def watch(self, channel: Channel, *, update_status: bool = True):
        self.gui.tray.change_icon("active")
        self.gui.channels.set_watching(channel)
        self.watching_channel.set(channel)
        if update_status:
            status_text = _("status", "watching").format(channel=channel.name)
            self.print(status_text)
            self.gui.status.update(status_text)

    def stop_watching(self):
        self.gui.clear_drop()
        self.watching_channel.clear()
        self.gui.channels.clear_watching()

    def restart_watching(self):
        self.gui.progress.stop_timer()
        self._watching_restart.set()

    @task_wrapper
    async def process_stream_state(self, channel_id: int, message: JsonType):
        msg_type = message["type"]
        channel = self.channels.get(channel_id)
        if channel is None:
            logger.error(f"Stream state change for a non-existing channel: {channel_id}")
            return
        if msg_type == "viewcount":
            if not channel.online:
                # if it's not online for some reason, set it so
                channel.check_online()
            else:
                viewers = message["viewers"]
                channel.viewers = viewers
                channel.display()
                # logger.debug(f"{channel.name} viewers: {viewers}")
        elif msg_type == "stream-down":
            channel.set_offline()
        elif msg_type == "stream-up":
            channel.check_online()
        elif msg_type == "commercial":
            # skip these
            pass
        else:
            logger.warning(f"Unknown stream state: {msg_type}")

    @task_wrapper
    async def process_stream_update(self, channel_id: int, message: JsonType):
        # message = {
        #     "channel_id": "12345678",
        #     "type": "broadcast_settings_update",
        #     "channel": "channel._login",
        #     "old_status": "Old title",
        #     "status": "New title",
        #     "old_game": "Old game name",
        #     "game": "New game name",
        #     "old_game_id": 123456,
        #     "game_id": 123456
        # }
        channel = self.channels.get(channel_id)
        if channel is None:
            logger.error(f"Broadcast settings update for a non-existing channel: {channel_id}")
            return
        if message["old_game"] != message["game"]:
            game_change = f", game changed: {message['old_game']} -> {message['game']}"
        else:
            game_change = ''
        logger.log(CALL, f"Channel update from websocket: {channel.name}{game_change}")
        # There's no information about channel tags here, but this event is triggered
        # when the tags change. We can use this to just update the stream data after the change.
        # Use 'check_online' to introduce a delay, allowing for multiple title and tags
        # changes before we update. This eventually calls 'on_channel_update' below.
        channel.check_online()

    def on_channel_update(
        self, channel: Channel, stream_before: Stream | None, stream_after: Stream | None
    ):
        """
        Called by a Channel when it's status is updated (ONLINE, OFFLINE, title/tags change).

        NOTE: 'stream_before' gets dealocated once this function finishes.
        """
        if stream_before is None:
            if stream_after is not None:
                # Channel going ONLINE
                if self.should_switch(channel):
                    # we can watch the channel, and we should
                    self.print(_("status", "goes_online").format(channel=channel.name))
                    self.watch(channel)
                else:
                    logger.info(f"{channel.name} goes ONLINE")
            else:
                # Channel was OFFLINE and stays that way
                logger.log(CALL, f"{channel.name} stays OFFLINE")
        else:
            watching_channel = self.watching_channel.get_with_default(None)
            # check if the watching channel was the one updated
            if watching_channel is not None and watching_channel == channel:
                # NOTE: In these cases, channel was the watching channel
                if not self.can_watch(channel):
                    # we can't watch it anymore
                    if stream_after is None:
                        # Channel going OFFLINE
                        self.print(_("status", "goes_offline").format(channel=channel.name))
                    else:
                        # Channel stays ONLINE, but we can't watch it anymore
                        logger.info(
                            f"{channel.name} status has been updated, switching... "
                            f"(🎁: {stream_before.drops_enabled and '✔' or '❌'} -> "
                            f"{stream_after.drops_enabled and '✔' or '❌'})"
                        )
                    self.change_state(State.CHANNEL_SWITCH)
                else:
                    # Channel stays ONLINE, and we can still watch it - no change
                    pass
            # NOTE: In these cases, it wasn't the watching channel
            elif stream_after is None:
                logger.info(f"{channel.name} goes OFFLINE")
            else:
                # Channel stays ONLINE, but has been updated
                logger.info(
                    f"{channel.name} status has been updated "
                    f"(🎁: {stream_before.drops_enabled and '✔' or '❌'} -> "
                    f"{stream_after.drops_enabled and '✔' or '❌'})"
                )
                if self.should_switch(channel):
                    # ... and we should watch it
                    self.watch(channel)
        if stream_after is not None:
            # a usable channel of this game is live again
            # (went online or switched back to it), no re-scan is needed for it
            game = stream_after.game
            if game is not None and self._has_live_game_channel(game):
                self._pending_rescans.discard(game)
        self._note_game_channels_lost(channel, stream_before, stream_after)
        channel.display()

    def _note_game_channels_lost(
        self, channel: Channel, stream_before: Stream | None, stream_after: Stream | None
    ) -> None:
        """
        Notes when the last online channel of an "Allowed Channels: All" game is lost
        (went offline or switched to a different game), and asks for a targeted
        re-scan of that game only.

        NOTE: this is called synchronously from the event loop, so it must only
        set flags and request a state change, not fetch anything itself.
        """
        if stream_before is None:
            # the channel was already offline, nothing was lost
            return
        game = stream_before.game
        if game is None or (stream_after is not None and stream_after.game == game):
            # only a title/tags update, or the game hasn't changed
            return
        if self.channels.get(channel.id) is not channel:
            # stale object, the cleanup already replaced or removed it
            return
        if game not in self.wanted_games or not self._is_no_acl_game(game):
            # not our concern: other games and fixed-channel (ACL) campaigns
            return
        if self._has_live_game_channel(game):
            # other usable channels of the game are still online
            return
        self._pending_rescans.add(game)
        watching = self.watching_channel.get_with_default(None)
        if not (
            watching is None
            or watching == channel
            or (watching.game is not None and watching.game == game)
        ):
            # another game is being mined right now, the re-scan is deferred
            # until this game becomes the active one again
            logger.info(
                f"All channels of {game.name} are gone, re-scan deferred "
                f"(currently mining {watching.game.name if watching.game is not None else 'nothing'})"
            )
            return
        in_cooldown = self._in_rescan_cooldown(game)
        if in_cooldown or self._rescan_now is not None:
            # avoid request thrashing; the queued re-scan is processed on the
            # next state change (promoted once the cooldown has passed)
            logger.info(f"All channels of {game.name} are gone, re-scan queued")
            return
        # this game was the actively mined one (or nothing is being mined)
        self._rescan_now = game
        logger.info(f"All channels of {game.name} are gone, re-scanning now")
        # don't clobber a pending reload request (change_state only guards EXIT)
        if self._state is not State.RESTART:
            self.change_state(State.CHANNEL_SWITCH)

    def _in_rescan_cooldown(self, game: Game) -> bool:
        """Whether the game's re-scan rate limit is still in effect."""
        last = self._rescan_last.get(game)
        return (last is not None
                and monotonic() - last < RESCAN_COOLDOWN.total_seconds())

    def _promote_pending_rescans(self) -> None:
        """Promotes a deferred re-scan once its game is actively mined again."""
        if not self._pending_rescans:
            return
        watching = self.watching_channel.get_with_default(None)
        active: Game | None = watching.game if watching is not None else None
        if active is None:
            # nothing is being mined: the first wanted game without a live
            # channel and out of cooldown gets it
            active = next(
                (game for game in self.wanted_games
                 if game in self._pending_rescans
                 and not self._in_rescan_cooldown(game)
                 and not self._has_live_game_channel(game)),
                None,
            )
        if (
            self._rescan_now is None
            and active is not None
            and active in self._pending_rescans
        ):
            if self._in_rescan_cooldown(active):
                # the cooldown hasn't passed yet, it'll be promoted later
                return
            self._pending_rescans.discard(active)
            self._rescan_now = active

    @task_wrapper
    async def process_drops(self, user_id: int, message: JsonType):
        # Message examples:
        # {"type": "drop-progress", data: {"current_progress_min": 3, "required_progress_min": 10}}
        # {"type": "drop-claim", data: {"drop_instance_id": ...}}
        msg_type: str = message["type"]
        if msg_type not in ("drop-progress", "drop-claim"):
            return
        drop_id: str = message["data"]["drop_id"]
        drop: TimedDrop | None = self._drops.get(drop_id)
        watching_channel: Channel | None = self.watching_channel.get_with_default(None)
        if msg_type == "drop-claim":
            if drop is None:
                logger.error(
                    f"Received a drop claim ID for a non-existing drop: {drop_id}\n"
                    f"Drop claim ID: {message['data']['drop_instance_id']}"
                )
                return
            drop.update_claim(message["data"]["drop_instance_id"])
            campaign = drop.campaign
            await drop.claim()
            drop.display()
            # About 4-20s after claiming the drop, next drop can be started
            # by re-sending the watch payload. We can test for it by fetching the current drop
            # via GQL, and then comparing drop IDs.
            await asyncio.sleep(4)
            if watching_channel is not None:
                for attempt in range(8):
                    context = await self.gql_request(
                        GQL_QUERIES["CurrentDrop"].with_variables(
                            {"channelID": str(watching_channel.id)}
                        )
                    )
                    drop_data: JsonType | None = (
                        context["data"]["currentUser"]["dropCurrentSession"]
                    )
                    if drop_data is None or drop_data["dropID"] != drop.id:
                        break
                    await asyncio.sleep(2)
            if campaign.can_earn(watching_channel):
                self.restart_watching()
            else:
                self.change_state(State.INVENTORY_FETCH)
            return
        assert msg_type == "drop-progress"
        if drop is not None:
            drop_text = (
                f"{drop.name} ({drop.campaign.game}, "
                f"{message['data']['current_progress_min']}/"
                f"{message['data']['required_progress_min']})"
            )
        else:
            drop_text = "<Unknown>"
        logger.log(CALL, f"Drop update from websocket: {drop_text}")
        if drop is not None and drop.can_earn(self.watching_channel.get_with_default(None)):
            # the received payload is for the drop we expected
            drop.update_minutes(message["data"]["current_progress_min"])

    @task_wrapper
    async def process_notifications(self, user_id: int, message: JsonType):
        if message["type"] == "create-notification":
            data: JsonType = message["data"]["notification"]
            if data["type"] in (
                "user_drop_reward_reminder_notification",  # drop confirmation
                "quests_viewer_reward_campaign_earned_emote",  # emote confirmation
                # badge confirmation?
            ):
                self.change_state(State.INVENTORY_FETCH)
                await self.gql_request(
                    GQL_QUERIES["NotificationsDelete"].with_variables(
                        {"input": {"id": data["id"]}}
                    )
                )

    async def get_auth(self) -> _AuthState:
        await self._auth_state.validate()
        return self._auth_state

    @asynccontextmanager
    async def request(
        self, method: str, url: URL | str, *, invalidate_after: datetime | None = None, **kwargs
    ) -> abc.AsyncIterator[aiohttp.ClientResponse]:
        session = await self.get_session()
        method = method.upper()
        if self.settings.proxy and "proxy" not in kwargs:
            kwargs["proxy"] = self.settings.proxy
        logger.debug(f"Request: ({method=}, {url=}, {kwargs=})")
        session_timeout = timedelta(seconds=session.timeout.total or 0)
        backoff = ExponentialBackoff(maximum=3*60)
        for delay in backoff:
            if self.gui.close_requested:
                raise ExitRequest()
            elif (
                invalidate_after is not None
                # account for the expiration landing during the request
                and datetime.now(timezone.utc) >= (invalidate_after - session_timeout)
            ):
                raise RequestInvalid()
            try:
                response: aiohttp.ClientResponse | None = None
                response = await self.gui.coro_unless_closed(
                    session.request(method, url, **kwargs)
                )
                assert response is not None
                logger.debug(f"Response: {response.status}: {response}")
                if response.status < 500:
                    # pre-read the response to avoid getting errors outside of the context manager
                    raw_response = await response.read()  # noqa
                    yield response
                    return
                self.print(_("error", "site_down").format(seconds=round(delay)))
            except aiohttp.ClientConnectorCertificateError:
                # for a case where SSL verification fails
                raise
            except (
                aiohttp.ClientConnectionError, asyncio.TimeoutError, aiohttp.ClientPayloadError
            ):
                # connection problems, retry
                if backoff.steps > 1:
                    # just so that quick retries that sometimes happen, aren't shown
                    self.print(
                        _("error", "no_connection").format(seconds=round(delay), url=str(url))
                    )
            finally:
                if response is not None:
                    response.release()
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self.gui.wait_until_closed(), timeout=delay)

    @overload
    async def gql_request(self, ops: GQLOperation) -> JsonType:
        ...

    @overload
    async def gql_request(self, ops: list[GQLOperation]) -> list[JsonType]:
        ...

    async def gql_request(
        self, ops: GQLOperation | list[GQLOperation]
    ) -> JsonType | list[JsonType]:
        gql_logger.debug(f"GQL Request: {ops}")
        backoff = ExponentialBackoff(maximum=60)
        # Use a flag to retry the request a single time, if a specific set of errors is encountered
        single_retry: bool = True
        for delay in backoff:
            async with self._qgl_limiter:
                auth_state = await self.get_auth()
                async with self.request(
                    "POST",
                    "https://gql.twitch.tv/gql",
                    json=ops,
                    headers=auth_state.headers(user_agent=self._client_type.USER_AGENT, gql=True),
                ) as response:
                    response_json: JsonType | list[JsonType] = await response.json()
            gql_logger.debug(f"GQL Response: {response_json}")
            orig_response = response_json
            if isinstance(response_json, list):
                response_list = response_json
            else:
                response_list = [response_json]
            force_retry: bool = False
            for response_json in response_list:
                # GQL error handling
                if "errors" in response_json:
                    for error_dict in response_json["errors"]:
                        if "message" in error_dict:
                            if (
                                single_retry
                                and error_dict["message"] in (
                                    "service error",
                                    "PersistedQueryNotFound",
                                )
                            ):
                                logger.error(
                                    f"Retrying a {error_dict['message']} for "
                                    f"{response_json['extensions']['operationName']}"
                                )
                                single_retry = False
                                if delay < 5:
                                    # overwrite the delay if too short
                                    delay = 5
                                force_retry = True
                                break
                            elif error_dict["message"] == "server error":
                                # nullify the key the error path points to
                                data_dict: JsonType = response_json["data"]
                                path: list[str] = error_dict.get("path", [])
                                for key in path[:-1]:
                                    data_dict = data_dict[key]
                                data_dict[path[-1]] = None
                                break
                            elif (
                                error_dict["message"] in (
                                    "service timeout",
                                    "request cancelled",
                                    "service unavailable",
                                    "context deadline exceeded",
                                )
                            ):
                                force_retry = True
                                break
                    else:
                        raise GQLException(response_json['errors'])
                # Other error handling
                elif "error" in response_json:
                    raise GQLException(
                        f"{response_json['error']}: {response_json['message']}"
                    )
                if force_retry:
                    break
            else:
                return orig_response
            await asyncio.sleep(delay)
        raise RuntimeError("Retry loop was broken")

    def _merge_data(self, primary_data: JsonType, secondary_data: JsonType) -> JsonType:
        merged = {}
        for key in set(chain(primary_data.keys(), secondary_data.keys())):
            in_primary = key in primary_data
            if in_primary and key in secondary_data:
                vp = primary_data[key]
                vs = secondary_data[key]
                if not isinstance(vp, type(vs)) or not isinstance(vs, type(vp)):
                    raise MinerException("Inconsistent merge data")
                if isinstance(vp, dict):  # both are dicts
                    merged[key] = self._merge_data(vp, vs)
                else:
                    # use primary value
                    merged[key] = vp
            elif in_primary:
                merged[key] = primary_data[key]
            else:  # in campaigns only
                merged[key] = secondary_data[key]
        return merged

    async def fetch_campaigns(
        self, campaigns_chunk: list[tuple[str, JsonType]]
    ) -> dict[str, JsonType]:
        campaign_ids: dict[str, JsonType] = dict(campaigns_chunk)
        auth_state = await self.get_auth()
        try:
            response_list: list[JsonType] = await self.gql_request(
                [
                    GQL_QUERIES["CampaignDetails"].with_variables(
                        {"channelLogin": str(auth_state.user_id), "dropID": cid}
                    )
                    for cid in campaign_ids
                ]
            )
        except GQLException as exc:
            # Twitch may refuse this query (integrity check) - the basic data is still usable
            # without the details there's no drops data, so these can't be used
            logger.warning(f"Unable to fetch the campaign details: {exc}")
            return {}
        fetched_data: dict[str, JsonType] = {}
        for response_json in response_list:
            user_data: JsonType | None = (response_json.get("data") or {}).get("user")
            campaign_data: JsonType | None = user_data and user_data.get("dropCampaign")
            if campaign_data:
                fetched_data[campaign_data["id"]] = campaign_data
        return self._merge_data(campaign_ids, fetched_data)

    async def fetch_inventory(self) -> None:
        status_update = self.gui.status.update
        status_update(_("gui", "status", "fetching_inventory"))
        # fetch in-progress campaigns (inventory)
        response = await self.gql_request(GQL_QUERIES["Inventory"])
        inventory: JsonType = response["data"]["currentUser"]["inventory"]
        ongoing_campaigns: list[JsonType] = inventory["dropCampaignsInProgress"] or []
        # this contains claimed benefit edge IDs, not drop IDs
        claimed_benefits: dict[str, datetime] = {
            b["id"]: timestamp(b["lastAwardedAt"]) for b in inventory["gameEventDrops"]
        }
        inventory_data: dict[str, JsonType] = {c["id"]: c for c in ongoing_campaigns}
        # fetch general available campaigns data (campaigns)
        available_list: list[JsonType] = []
        try:
            response = await self.gql_request(GQL_QUERIES["Campaigns"])
        except GQLException as exc:
            # Since September 2026, Twitch refuses this query for the clients we can use
            # (integrity check). The campaigns are discovered from the channels instead.
            logger.warning(f"Unable to fetch the campaigns list: {exc}")
        else:
            current_user: JsonType | None = response["data"].get("currentUser")
            if current_user is not None:
                available_list = current_user.get("dropCampaigns") or []
        applicable_statuses = ("ACTIVE", "UPCOMING")
        available_campaigns: dict[str, JsonType] = {
            c["id"]: c
            for c in available_list
            if c["status"] in applicable_statuses  # that are currently not expired
        }
        # fetch detailed data for each campaign, in chunks
        status_update(_("gui", "status", "fetching_campaigns"))
        fetch_campaigns_tasks: list[asyncio.Task[Any]] = [
            asyncio.create_task(self.fetch_campaigns(campaigns_chunk))
            for campaigns_chunk in chunk(available_campaigns.items(), 20)
        ]
        try:
            for coro in asyncio.as_completed(fetch_campaigns_tasks):
                chunk_campaigns_data = await coro
                # merge the inventory and campaigns datas together
                inventory_data = self._merge_data(inventory_data, chunk_campaigns_data)
        except Exception:
            # asyncio.as_completed doesn't cancel tasks on errors
            for task in fetch_campaigns_tasks:
                task.cancel()
            raise
        # campaigns Twitch didn't list for us can still be found on the live channels
        if self.settings.campaign_discovery:
            try:
                discovered: dict[str, JsonType] = await self.discover_campaigns(inventory_data)
            except MinerException as exc:
                logger.warning(f"Campaign discovery failed: {exc}")
            else:
                for campaign_id, campaign_data in discovered.items():
                    inventory_data.setdefault(campaign_id, campaign_data)
        # filter out invalid campaigns
        for campaign_id in list(inventory_data.keys()):
            if inventory_data[campaign_id].get("game") is None:
                del inventory_data[campaign_id]

        if self.settings.dump:
            # dump the campaigns data to the dump file
            with open(DUMP_PATH, 'a', encoding="utf8") as file:
                # we need to pre-process the inventory dump a little
                dump_data: JsonType = deepcopy(inventory_data)
                for campaign_data in dump_data.values():
                    # replace ACL lists with a simple text description
                    if (
                        campaign_data["allow"]
                        and campaign_data["allow"].get("isEnabled", True)
                        and campaign_data["allow"]["channels"]
                    ):
                        # simply count the channels included in the ACL
                        campaign_data["allow"]["channels"] = (
                            f"{len(campaign_data['allow']['channels'])} channels"
                        )
                    # replace drop instance IDs, so they don't include user IDs
                    for drop_data in campaign_data["timeBasedDrops"]:
                        if "self" in drop_data and drop_data["self"]["dropInstanceID"]:
                            drop_data["self"]["dropInstanceID"] = "..."
                json.dump(dump_data, file, indent=4, sort_keys=True)
                file.write("\n\n")  # add 2x new line spacer
                json.dump(inventory["gameEventDrops"], file, indent=4, sort_keys=True, default=str)

        # use the merged data to create campaign objects
        campaigns: list[DropsCampaign] = [
            DropsCampaign(self, campaign_data, claimed_benefits)
            for campaign_data in inventory_data.values()
        ]
        campaigns.sort(key=lambda c: c.active, reverse=True)
        campaigns.sort(key=lambda c: c.upcoming and c.starts_at or c.ends_at)
        campaigns.sort(key=lambda c: c.eligible, reverse=True)

        self._drops.clear()
        self.gui.inv.clear()
        self.inventory.clear()
        self._mnt_triggers.clear()
        switch_triggers: set[datetime] = set()
        next_hour = datetime.now(timezone.utc) + timedelta(hours=1)
        # add the campaigns to the internal inventory
        for campaign in campaigns:
            self._drops.update({drop.id: drop for drop in campaign.drops})
            if campaign.can_earn_within(next_hour):
                switch_triggers.update(campaign.time_triggers)
            self.inventory.append(campaign)
            self._campaigns[campaign.id] = campaign
        # concurrently add the campaigns into the GUI
        # NOTE: this fetches pictures from the CDN, so might be slow without a cache
        status_update(
            _("gui", "status", "adding_campaigns").format(counter=f"(0/{len(campaigns)})")
        )
        add_campaign_tasks: list[asyncio.Task[None]] = [
            asyncio.create_task(self.gui.inv.add_campaign(campaign))
            for campaign in campaigns
        ]
        try:
            for i, coro in enumerate(asyncio.as_completed(add_campaign_tasks), start=1):
                await coro
                status_update(
                    _("gui", "status", "adding_campaigns").format(
                        counter=f"({i}/{len(campaigns)})"
                    )
                )
                # this is needed here explicitly, because cache reads from disk don't raise this
                if self.gui.close_requested:
                    raise ExitRequest()
        except Exception:
            # asyncio.as_completed doesn't cancel tasks on errors
            for task in add_campaign_tasks:
                task.cancel()
            raise
        self._mnt_triggers.extend(sorted(switch_triggers))
        # trim out all triggers that we're already past
        now = datetime.now(timezone.utc)
        while self._mnt_triggers and self._mnt_triggers[0] <= now:
            self._mnt_triggers.popleft()
        # NOTE: maintenance task is restarted at the end of each inventory fetch
        if self._mnt_task is not None and not self._mnt_task.done():
            self._mnt_task.cancel()
        self._mnt_task = asyncio.create_task(self._maintenance_task())

    def get_active_campaign(self, channel: Channel | None = None) -> DropsCampaign | None:
        if not self.wanted_games:
            return None
        watching_channel = self.watching_channel.get_with_default(channel)
        if watching_channel is None:
            # if we aren't watching anything, we can't earn any drops
            return None
        campaigns: list[DropsCampaign] = []
        for campaign in self.inventory:
            if campaign.can_earn(watching_channel):
                campaigns.append(campaign)
        if campaigns:
            campaigns.sort(key=lambda c: c.remaining_minutes)
            return campaigns[0]
        return None

    async def get_live_streams(
        self, game: Game, *, limit: int = 20, drops_enabled: bool = True,
        sort: str | None = None,
    ) -> list[Channel]:
        filters: list[str] = []
        if drops_enabled:
            filters.append("DROPS_ENABLED")
        options: dict[str, JsonType] = {
            "includeRestricted": ["SUB_ONLY_LIVE"],
            "systemFilters": filters,
        }
        if sort is not None:
            options["sort"] = sort
        try:
            response = await self.gql_request(
                GQL_QUERIES["GameDirectory"].with_variables({
                    "limit": limit,
                    "slug": game.slug,
                    "options": options,
                })
            )
        except GQLException as exc:
            raise MinerException(f"Game: {game.slug}") from exc
        # a not-found game comes back as null (and isn't a GQL error)
        game_data: JsonType | None = response["data"].get("game")
        if game_data is not None:
            return [
                Channel.from_directory(
                    self, stream_channel_data["node"], drops_enabled=drops_enabled
                )
                for stream_channel_data in game_data["streams"]["edges"]
                if stream_channel_data["node"]["broadcaster"] is not None
            ]
        return []

    async def rescan_game_channels(self, game: Game) -> None:
        """
        Fetches fresh top channels for a single "Allowed Channels: All" game,
        without disturbing the channels of other games or ACL-based channels.

        NOTE: only the state machine may mutate the channel set and topics, so
        this must only be awaited from within it.
        """
        if self._has_live_game_channel(game) or not self._is_no_acl_game(game):
            # the situation has already changed (or a full scan ran in the meantime)
            return
        self._rescan_last[game] = monotonic()
        try:
            game_channels = await self.get_live_streams(
                game, limit=NO_ACL_CHANNEL_COUNT, drops_enabled=True,
                sort="VIEWER_COUNT",
            )
        except MinerException as exc:
            logger.warning(f"Re-scan of {game.name} failed: {exc}")
            # keep it pending, so the next switch attempt retries it
            self._pending_rescans.add(game)
            return
        if not game_channels:
            # nothing is live right now, retry on the next switch attempt
            self._pending_rescans.add(game)
            return
        logger.info(f"Re-scanned {game.name}: {len(game_channels)} channels found")
        added_any: bool = False
        to_add_topics: list[WebsocketTopic] = []
        for channel in game_channels:
            existing = self.channels.get(channel.id)
            if existing is not None:
                # replace the stale object with the fresh directory data
                existing.remove()
                # keep the ACL status, so a fixed-channel campaign channel
                # doesn't lose its priority/cleanup behavior
                channel.acl_based = existing.acl_based
                channel.drops_assumed = existing.drops_assumed
                channel.display(add=True)
                if self.watching_channel.get_with_default(None) is existing:
                    # the stale object was the one being watched - relink it
                    self.watch(channel, update_status=False)
                self.channels[channel.id] = channel
                added_any = True
                continue
            if len(self.channels) >= MAX_CHANNELS:
                # make room by evicting one offline, non-ACL channel
                if not self._evict_for_rescan():
                    logger.warning(
                        f"Channel limit reached, skipping {channel.name} "
                        f"(re-scan of {game.name})"
                    )
                    continue
            self.channels[channel.id] = channel
            channel.display(add=True)
            added_any = True
            to_add_topics.append(
                WebsocketTopic("Channel", "StreamState", channel.id, self.process_stream_state)
            )
            to_add_topics.append(
                WebsocketTopic("Channel", "StreamUpdate", channel.id, self.process_stream_update)
            )
        if added_any:
            self._pending_rescans.discard(game)
        else:
            # nothing was added (e.g. the channel limit is full), retry later
            self._pending_rescans.add(game)
        if to_add_topics:
            self.websocket.add_topics(to_add_topics)

    def _evict_for_rescan(self) -> bool:
        """
        Evicts one offline, non-ACL, non-watching channel to make room for a new one.
        Returns True on success.
        """
        watching = self.watching_channel.get_with_default(None)
        for channel in self.channels.values():
            if (
                channel is not watching
                and not channel.acl_based
                # 'offline' excludes channels that just got a stream-up event
                and channel.offline
            ):
                self.websocket.remove_topics([
                    WebsocketTopic.as_str("Channel", "StreamState", channel.id),
                    WebsocketTopic.as_str("Channel", "StreamUpdate", channel.id),
                ])
                del self.channels[channel.id]
                channel.remove()
                return True
        return False

    async def fetch_available_drops(
        self, channel_ids: abc.Iterable[int]
    ) -> dict[int, list[JsonType]]:
        """
        Asks Twitch which drop campaigns the account can progress on each of the channels.
        """
        ops: list[GQLOperation] = [
            GQL_QUERIES["AvailableDrops"].with_variables({"channelID": str(channel_id)})
            for channel_id in channel_ids
        ]
        available: dict[int, list[JsonType]] = {}
        for ops_chunk in chunk(ops, 20):
            try:
                response_list: list[JsonType] = await self.gql_request(ops_chunk)
            except GQLException as exc:
                # one failed batch shouldn't lose the answers of all the others
                logger.warning(f"Available drops: a batch of channels failed: {exc}")
                continue
            for response_json in response_list:
                channel_data: JsonType | None = (response_json.get("data") or {}).get("channel")
                if channel_data is not None:
                    available[int(channel_data["id"])] = (
                        channel_data.get("viewerDropCampaigns") or []
                    )
        return available

    def _campaign_from_available(
        self,
        campaign_data: JsonType,
        known: dict[str, JsonType],
        skipped: dict[str, int] | None = None,
    ) -> JsonType | None:
        """
        Converts a campaign reported by the available drops query into the inventory format.

        Missing drop details are filled in from the campaign. Drops that can't be earned by
        watching (no watch time, or subscriptions required) are left out. When a campaign
        can't be used, the reason is counted in `skipped`.
        """
        def skip(reason: str) -> None:
            if skipped is not None:
                skipped[reason] = skipped.get(reason, 0) + 1

        game_data: JsonType | None = campaign_data.get("game")
        if not game_data or "id" not in game_data:
            skip("no game")
            return None
        game_name: str = game_data.get("displayName") or game_data.get("name") or ""
        # keep the spelling from the priority list, since the game matching uses names
        for priority_name in self.settings.priority:
            if priority_name.casefold() == game_name.casefold():
                game_name = priority_name
                break
        box_art: str = (
            f"https://static-cdn.jtvnw.net/ttv-boxart/{game_data['id']}_IGDB-285x380.jpg"
        )
        # the linked status is only known from other campaigns of the same game
        linked: bool = True
        for known_data in known.values():
            known_game: JsonType | None = known_data.get("game")
            if (
                known_game is not None
                and str(known_game.get("id")) == str(game_data["id"])
                and known_data.get("self") is not None
            ):
                linked = bool(known_data["self"].get("isAccountConnected", True))
                break
        campaign_name: str = campaign_data.get("name") or game_name
        campaign_start: str = (
            # in the same format as Twitch's own dates, which the campaign parser expects
            campaign_data.get("startAt")
            or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        )
        campaign_end: str | None = campaign_data.get("endAt")
        drops: list[JsonType] = []
        for drop_data in campaign_data.get("timeBasedDrops") or []:
            required_minutes: int = drop_data.get("requiredMinutesWatched") or 0
            if not drop_data.get("id") or required_minutes <= 0 or drop_data.get("requiredSubs"):
                continue  # not earnable by watching
            drop_end: str | None = drop_data.get("endAt") or campaign_end
            if drop_end is None:
                continue
            drop_name: str = drop_data.get("name") or campaign_name
            benefit_edges: list[JsonType] = []
            for edge in drop_data.get("benefitEdges") or []:
                benefit: JsonType = dict(edge.get("benefit") or {})
                if "id" not in benefit:
                    continue
                benefit.setdefault("name", drop_name)
                benefit.setdefault("distributionType", "UNKNOWN")
                if not benefit.get("imageAssetURL"):
                    benefit["imageAssetURL"] = box_art
                benefit_edges.append({**edge, "benefit": benefit})
            drops.append({
                "id": drop_data["id"],
                "name": drop_name,
                "startAt": drop_data.get("startAt") or campaign_start,
                "endAt": drop_end,
                "requiredMinutesWatched": required_minutes,
                "preconditionDrops": drop_data.get("preconditionDrops"),
                "benefitEdges": benefit_edges,
            })
        if not drops:
            skip("no drops earnable by watching")
            return None
        return {
            "id": campaign_data["id"],
            "name": campaign_name,
            "game": {
                "id": game_data["id"],
                "name": game_name,
                "displayName": game_name,
                "boxArtURL": box_art,
            },
            "self": {"isAccountConnected": linked},
            "accountLinkURL": campaign_data.get("detailsURL") or "",
            "startAt": min(drop["startAt"] for drop in drops),
            "endAt": campaign_end or max(drop["endAt"] for drop in drops),
            "status": "ACTIVE",
            "allow": {"channels": [], "isEnabled": True},
            "timeBasedDrops": drops,
        }

    async def scan_drops_streams(self) -> dict[str, list[JsonType]]:
        """
        Lists the live streams Twitch marks as drops-enabled, across every game.

        Returns the most watched channels of each game, by game ID. The stream list is
        public, so the request is made without the account's authorization.
        """
        game_channels: dict[str, list[JsonType]] = {}
        headers = {
            "Client-Id": self._client_type.CLIENT_ID,
            "User-Agent": self._client_type.USER_AGENT,
            "Content-Type": "application/json",
        }
        for sort in DISCOVERY_SCAN_SORTS:
            cursor: str | None = None
            for page in range(DISCOVERY_SCAN_PAGES):
                after: str = f', after: {json.dumps(cursor)}' if cursor else ''
                query: str = (
                    "{ streams(first: 30%s, options: {systemFilters: [DROPS_ENABLED], "
                    "sort: %s}) { edges { cursor node { game { id name displayName slug } "
                    "broadcaster { id login displayName } } } pageInfo { hasNextPage } } }"
                ) % (after, sort)
                async with self._qgl_limiter:
                    async with self.request(
                        "POST", "https://gql.twitch.tv/gql", json={"query": query}, headers=headers
                    ) as response:
                        response_json: JsonType = await response.json()
                streams: JsonType | None = (response_json.get("data") or {}).get("streams")
                if response_json.get("errors") or not streams:
                    raise MinerException(f"Drops scan failed: {response_json.get('errors')}")
                edges: list[JsonType] = streams.get("edges") or []
                for edge in edges:
                    node: JsonType = edge.get("node") or {}
                    game: JsonType | None = node.get("game")
                    broadcaster: JsonType | None = node.get("broadcaster")
                    if not game or not broadcaster:
                        continue
                    channels = game_channels.setdefault(str(game["id"]), [])
                    # the first sort is by viewers, so the most watched channels come first
                    if (
                        len(channels) < DISCOVERY_CHANNELS_PER_GAME
                        and all(c["id"] != str(broadcaster["id"]) for c in channels)
                    ):
                        channels.append({
                            "id": str(broadcaster["id"]),
                            "name": broadcaster["login"],
                            "displayName": broadcaster.get("displayName") or broadcaster["login"],
                            "gameName": game.get("displayName") or game.get("name") or "",
                            "gameSlug": game.get("slug") or "",
                        })
                if not edges or not (streams.get("pageInfo") or {}).get("hasNextPage"):
                    break
                cursor = edges[-1].get("cursor")
                if not cursor:
                    break
        return game_channels

    async def _priority_game_channels(self, known: dict[str, JsonType]) -> dict[str, list[JsonType]]:
        """
        The channels of the priority list games and the in-progress ones, asked explicitly.
        """
        games: dict[str, Game] = {}
        for game_name in self.settings.priority:
            # only the slug made from the name is needed for the directory query
            games.setdefault(game_name.casefold(), Game({"id": 0, "name": game_name}))
        for campaign_data in known.values():
            if campaign_data.get("game") is not None:
                game = Game(campaign_data["game"])
                games.setdefault(game.name.casefold(), game)
        game_channels: dict[str, list[JsonType]] = {}
        for key, game in games.items():
            try:
                live = await self.get_live_streams(
                    game, limit=DISCOVERY_CHANNELS_PER_GAME, sort="VIEWER_COUNT"
                )
            except (MinerException, KeyError, TypeError, ValueError):
                logger.warning(f"Campaign discovery: unable to fetch the streams of {game.name}")
                continue
            game_channels[key] = [
                {
                    "id": str(channel.id),
                    "name": channel._login,
                    "displayName": channel._display_name or channel._login,
                    "gameName": game.name,
                    "gameSlug": game.slug,
                }
                for channel in live
            ]
        return game_channels

    def _load_drops_games(self) -> JsonType:
        """
        Loads the games found with drops before, dropping the ones not seen for a while.
        """
        try:
            remembered: JsonType = json_load(DROPS_GAMES_PATH, {}, merge=False)
        except (OSError, ValueError):
            return {}
        cutoff = datetime.now(timezone.utc) - timedelta(days=DISCOVERY_REMEMBER_DAYS)
        kept: JsonType = {}
        for game_id, entry in remembered.items():
            try:
                if datetime.fromisoformat(entry["seen"]) >= cutoff and entry["name"]:
                    kept[str(game_id)] = entry
            except (KeyError, TypeError, ValueError):
                continue
        return kept

    def _save_drops_games(self, remembered: JsonType) -> None:
        try:
            json_save(DROPS_GAMES_PATH, remembered, sort=True)
        except OSError as exc:
            logger.warning(f"Unable to save the games with drops: {exc}")

    async def _add_remembered_games(
        self, game_channels: dict[str, list[JsonType]], remembered: JsonType
    ) -> None:
        """
        Looks up the channels of games that had drops before, but the scan didn't list.
        """
        # games already searched are keyed by ID (scan) or by name (priority list)
        searched_names = {
            key.removeprefix("name:")
            for key in game_channels
            if key.startswith("name:")
        }
        missing = [
            (game_id, entry) for game_id, entry in remembered.items()
            if game_id not in game_channels
            and entry["name"].casefold() not in searched_names
        ]
        # the most recently seen first
        missing.sort(key=lambda item: item[1]["seen"], reverse=True)
        for game_id, entry in missing[:DISCOVERY_REMEMBERED_MAX]:
            game_data: JsonType = {"id": game_id, "name": entry["name"]}
            if entry.get("slug"):
                game_data["slug"] = entry["slug"]
            game = Game(game_data)
            try:
                live = await self.get_live_streams(game, limit=DISCOVERY_CHANNELS_PER_GAME)
            except (MinerException, KeyError, TypeError, ValueError):
                continue
            if live:
                game_channels[game_id] = [
                    {
                        "id": str(channel.id),
                        "name": channel._login,
                        "displayName": channel._display_name or channel._login,
                        "gameName": entry["name"],
                        "gameSlug": entry.get("slug") or "",
                    }
                    for channel in live
                ]

    async def discover_campaigns(self, known: dict[str, JsonType]) -> dict[str, JsonType]:
        """
        Finds the drop campaigns available to the account by asking live channels about them.

        Since September 2026 Twitch refuses the campaigns list query for the clients the
        application can use, but each channel still reports the drops it offers the account.
        Every live drops-enabled stream on Twitch is listed, and the most watched channels of
        each game are asked about their drops. Results are reused for a while, to keep the
        amount of requests down.
        """
        now: float = time()
        if self._discovery_cache is not None and now - self._discovery_cache[0] < (
            DISCOVERY_CACHE_MINUTES * 60
        ):
            cached: dict[str, JsonType] = self._discovery_cache[1]
            return {cid: deepcopy(data) for cid, data in cached.items() if cid not in known}
        self.gui.status.update(_("gui", "status", "fetching_campaigns"))
        try:
            game_channels = await self.scan_drops_streams()
        except (MinerException, KeyError, TypeError, ValueError) as exc:
            logger.warning(f"{exc} - the priority list games will still be searched")
            game_channels = {}
        # the priority list games (and the in-progress ones) are always searched
        # explicitly, so their campaigns are found even when the scan doesn't
        # list a game (or failed); when the scan knows a game, its key (the
        # game ID) and its channel data are kept, and only channels the scan
        # missed are appended to it
        name_to_scan_key: dict[str, str] = {}
        for scan_key, scan_channels in game_channels.items():
            for scan_channel in scan_channels:
                name = (scan_channel.get("gameName") or "").casefold()
                if name:
                    name_to_scan_key.setdefault(name, scan_key)
        try:
            priority_channels = await self._priority_game_channels(known)
        except (MinerException, KeyError, TypeError, ValueError) as exc:
            logger.warning(f"Priority list search failed: {exc}")
            priority_channels = {}
        for key, channels in priority_channels.items():
            if not channels:
                # nothing is live, the remembered-games lookup can still find it
                continue
            scan_key = name_to_scan_key.get(key)
            if scan_key is None:
                # the scan doesn't know this game, it gets its own (name) key;
                # the prefix keeps a purely numeric game name from colliding
                # with a scan game ID
                game_channels[f"name:{key}"] = channels
                continue
            existing = game_channels[scan_key]
            seen_ids = {c["id"] for c in existing}
            game_channels[scan_key] = [
                *existing,
                *(c for c in channels if c["id"] not in seen_ids),
            ]
        remembered: JsonType = self._load_drops_games()
        await self._add_remembered_games(game_channels, remembered)
        excluded: set[str] = {name.casefold() for name in self.settings.exclude}
        channel_info: dict[int, JsonType] = {}
        channel_game: dict[int, str] = {}
        for game_key, channels_data in game_channels.items():
            for channel_data in channels_data:
                if channel_data["gameName"].casefold() in excluded:
                    continue
                channel_id = int(channel_data["id"])
                channel_info[channel_id] = channel_data
                channel_game[channel_id] = game_key
        if not channel_info:
            return {}
        available = await self.fetch_available_drops(channel_info)
        discovered: dict[str, JsonType] = {}
        seen_on: dict[str, set[int]] = {}
        skipped: dict[str, int] = {}
        rejected: set[str] = set()
        for channel_id, campaigns_data in available.items():
            if channel_id not in channel_info:
                continue
            for campaign_data in campaigns_data:
                campaign_id: str | None = campaign_data.get("id")
                if not campaign_id:
                    continue
                if campaign_id in rejected:
                    continue
                if campaign_id not in discovered:
                    converted = self._campaign_from_available(campaign_data, known, skipped)
                    if converted is None:
                        rejected.add(campaign_id)
                        continue
                    if converted["game"]["name"].casefold() in excluded:
                        rejected.add(campaign_id)
                        skipped["excluded game"] = skipped.get("excluded game", 0) + 1
                        continue
                    # use Twitch's own URL name of the game, when the scan provided it
                    slug: str = channel_info[channel_id].get("gameSlug") or ""
                    if slug and channel_game[channel_id] == str(converted["game"]["id"]):
                        converted["game"]["slug"] = slug
                    discovered[campaign_id] = converted
                    seen_on[campaign_id] = set()
                seen_on[campaign_id].add(channel_id)
        for campaign_id, seen in seen_on.items():
            # Twitch doesn't tell if a campaign is limited to some channels. If it showed
            # up on every channel asked for that game, assume it's game-wide (no limit),
            # otherwise limit it to the channels it showed up on.
            asked: set[int] = {
                channel_id
                for channel_id, game_key in channel_game.items()
                if game_key in {channel_game[seen_id] for seen_id in seen}
            }
            if len(asked) > 1 and seen != asked:
                discovered[campaign_id]["allow"]["channels"] = [
                    {key: channel_info[channel_id][key] for key in ("id", "name", "displayName")}
                    for channel_id in sorted(seen)
                ]
        # remember the games with drops, so the next scans look them up even when
        # Twitch's stream list leaves them out
        seen_at: str = datetime.now(timezone.utc).isoformat()
        for data in discovered.values():
            game_data: JsonType = data["game"]
            remembered[str(game_data["id"])] = {
                "name": game_data["name"],
                "slug": game_data.get("slug") or Game(game_data).slug,
                "seen": seen_at,
            }
        self._save_drops_games(remembered)
        self._discovery_cache = (now, deepcopy(discovered))
        answered: int = sum(1 for campaigns_data in available.values() if campaigns_data)
        found_games: int = len({str(data["game"]["id"]) for data in discovered.values()})
        skipped_text: str = ", ".join(f"{reason}: {n}" for reason, n in sorted(skipped.items()))
        logger.info(
            f"Campaign discovery: {len(discovered)} campaign(s) of {found_games} game(s) found. "
            f"Scanned {len(game_channels)} game(s), asked {len(channel_info)} channel(s), "
            f"{len(available)} answered, {answered} with drops. "
            f"Skipped campaigns: {skipped_text or 'none'}"
        )
        self.print(
            f"Drops scan: {len(discovered)} campaign(s) of {found_games} game(s) found, "
            f"{len(channel_info)} channel(s) of {len(game_channels)} game(s) checked"
        )
        return {cid: data for cid, data in discovered.items() if cid not in known}

    async def bulk_check_online(self, channels: abc.Iterable[Channel]):
        """
        Utilize batch GQL requests to check ONLINE status for a lot of channels at once.
        Also handles the drops_enabled check (if enabled).
        """
        acl_streams_map: dict[int, JsonType] = {}
        stream_gql_ops: list[GQLOperation] = [channel.stream_gql for channel in channels]
        if not stream_gql_ops:
            # shortcut for nothing to process
            # NOTE: Have to do this here, becase "channels" can be any iterable
            return
        stream_gql_tasks: list[asyncio.Task[list[JsonType]]] = [
            asyncio.create_task(self.gql_request(stream_gql_chunk))
            for stream_gql_chunk in chunk(stream_gql_ops, 20)
        ]
        try:
            for coro in asyncio.as_completed(stream_gql_tasks):
                response_list: list[JsonType] = await coro
                for response_json in response_list:
                    channel_data: JsonType = response_json["data"]["user"]
                    if channel_data is not None:
                        acl_streams_map[int(channel_data["id"])] = channel_data
        except Exception:
            # asyncio.as_completed doesn't cancel tasks on errors
            for task in stream_gql_tasks:
                task.cancel()
            raise
        # for all channels with an active stream, check the available drops as well
        acl_available_drops_map: dict[int, list[JsonType]] = {}
        if self.settings.available_drops_check:
            available_gql_ops: list[GQLOperation] = [
                GQL_QUERIES["AvailableDrops"].with_variables({"channelID": str(channel_id)})
                for channel_id, channel_data in acl_streams_map.items()
                if channel_data["stream"] is not None  # only do this for ONLINE channels
            ]
            available_gql_tasks: list[asyncio.Task[list[JsonType]]] = [
                asyncio.create_task(self.gql_request(available_gql_chunk))
                for available_gql_chunk in chunk(available_gql_ops, 20)
            ]
            try:
                for coro in asyncio.as_completed(available_gql_tasks):
                    response_list = await coro
                    for response_json in response_list:
                        available_info: JsonType = response_json["data"]["channel"]
                        acl_available_drops_map[int(available_info["id"])] = (
                            available_info["viewerDropCampaigns"] or []
                        )
            except Exception:
                # asyncio.as_completed doesn't cancel tasks on errors
                for task in available_gql_tasks:
                    task.cancel()
                raise
        for channel in channels:
            channel_id = channel.id
            if channel_id not in acl_streams_map:
                continue
            channel_data = acl_streams_map[channel_id]
            if channel_data["stream"] is None:
                continue
            available_drops: list[JsonType] = acl_available_drops_map.get(channel_id, [])
            channel.external_update(channel_data, available_drops)
