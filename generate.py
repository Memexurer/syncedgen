import requests
import select
import socket
import hashlib
import json
import collections
import time
from urllib.parse import urlencode
from urllib3.util import Retry
from requests.adapters import HTTPAdapter
import ssl

ssl._create_default_https_context = ssl._create_unverified_context

i_be_cooling_for_real = "secret... sorry..."

cool = {
    "proxies": {
    }
}

appId = "aec575b4b14c87016dce3764fea239fb"
globalSigKey = "0d88135dd851f81f9601e477b261a137"
urlParams = {
    "account_plat_type": 131,
    "app_id": appId,
    "lang_type": "en",
    "os": 5,
    "source": 32,
    "channelid": 131,
    "conn": 0,
    "gameid": 28011,
    "sdk_version": "2.0",
}


def tecentIntl(
    endpoint, requestBody, retardedContentType=False, host="li-sg", replace_params={}, sigkey=globalSigKey
):
    serialized = "?" + urlencode(
        dict(sorted({**(replace_params if replace_params else urlParams)}.items()))
    )
    serialized = serialized.replace("%2F", "/")

    signature = hashlib.md5(
        f"{endpoint}{serialized}{requestBody}{sigkey}".encode()
    ).hexdigest()
    url = f"https://{host}.intlgame.com{endpoint}{serialized}&sig={signature}"

    headers = {
        "user-agent": "",
        "content-type": "application/x-www-form-urlencoded"
        if retardedContentType
        else "application/json",
    }

    s = requests.Session()
    retries = Retry(
        total=5,
        backoff_factor=0.1,
        status_forcelist=[502, 503, 504],
        allowed_methods={'POST'},
    )
    s.proxies = cool["proxies"]
    s.mount('https://', HTTPAdapter(max_retries=retries))

    response = s.post(url, headers=headers, data=requestBody, timeout=10)
    print(response.request.headers)
    x = response.json()
    if x["ret"] != 0:
        if x["ret"] == 35203008:
            raise Exception("RATELIMIT KURWO")
        raise Exception(x["msg"])
    return x


def gen_first(email):
    req = tecentIntl(
        "/account/sendcode",
        json.dumps({"account": email, "account_type": 1, "code_type": 2}),
    )
    if req["msg"] != "Success":
        print(email)
        raise Exception("sendcode err: " + str(req))


def gen_second(email, code, callback, password="2965de900b881396602801f111544f26"):
    register = tecentIntl(
        "/account/loginwithcode",
        json.dumps(
            {
                "verify_code": code,
                "account": email,
                "account_type": 1,
                "password": password,
            }
        ),
    )
    tecentAuth = tecentIntl(
        "/v2/auth/login",
        json.dumps(
            {
                "channel_dis": "Windows",
                "channel_info": {
                    "account": email,
                    "account_plat_type": 131,
                    "account_token": register["token"],
                    "account_type": 1,
                    "account_uid": register["uid"],
                    "is_login": False,
                    "lang_type": "en",
                    "openid": register["uid"],
                    "phone_area_code": "",
                    "token": register["token"],  
                },
                "device_info": {
                    "app_version": "",
                    "client_region": "PL",
                    "cpu_name": "AMD Ryzen 5 3600 6-Core Processor              ",
                    "device_brand": "System manufacturer",
                    "device_model": "System Product Name",
                    "guest_id": "523bbdd4-252a-4d04-8840-d6ea8e2806f0",
                    "lang_type": "pl",
                    "network_type": 7,
                    "ram_total": 16384,
                    "rom_total": 953867,
                    "root_info": "",
                    "screen_dpi": "",
                    "screen_height": 1440,
                    "screen_width": 2560,
                    "xwid": "79372dd523ebe2f13263732a31a4edff4021bd2f14afdc806c402bf96c33bf"
                },
                "lang_type": "en",
                "login_extra_info": "{}"
            }
        ),
        True,
        host="na",
    )

    pf = tecentAuth["pf"]
    pf_key = tecentAuth["pf_key"]
    print(pf, pf_key)

    openid = tecentAuth["openid"]
    token = tecentAuth["token"]
    ticket = requests.get(
        f"https://usw2-realm.iegcom.com/v2/g6/auth/1962479523?authtype=4&os=5&channelid=131&sdkversion=&openid={openid}&token={token}&expired=0",
        headers={},
        **cool
    ).json()["data"]["login_ticket"]

    if requests.post(i_be_cooling_for_real, json={"ticket": ticket}, **cool).status_code != 204:
        raise Exception("uhhh")

    ts = int(time.time())

    print(token)
    print(openid)
    
    auth = requests.post('https://awsnaor.client.pgos.intlgame.com/auth/authentication', headers={
        'accept': '*/*',
        'protoversion': '1',
        'sdkversion': '0.19.1.1139',
        'titleid': '4njtt',
        'titleregionid': 'awsnaor_4njtt_237',
        'seq': '10001',
        'content-type': 'application/json;charset=UTF-8',
        'user-agent': 'sisiphus' # licik - issue for you to fix: user-agent is not sent by the game, but requests lib adds one if there isnt any, so find a way to bypass it!
    }, json={
        'account_open_id': openid, 
        'account_provider': 1, 
        'account_token': token, 
        'secret_id': '48T2',
        'timestamp': ts,
        'os': 2,
        'extra_param': {
            'account_channel': '131', 
            'support_fas_account_id': "true"
        },
        'signature': hashlib.sha256(f"account_id=&account_open_id={openid}&account_provider=1&account_token={token}&extra_param=account_channel=131&support_fas_account_id=true&os=2&secret_id=48T2&secret_key=4BHX-AJJK-O2EH-FC6D&timestamp={ts}&title_id=4njtt&title_region_id=awsnaor_4njtt_237".encode()).hexdigest(),
        'title_id': '4njtt',
        'title_region_id': 'awsnaor_4njtt_237',
    }, **cool).json()
    print(auth)
    if auth["result"] != 0:
        raise Exception(auth["msg"])

    update = requests.post("https://awsnaor.client.pgos.intlgame.com/player/update_player_info", headers = {
        'accept': '*/*',
        'playerid': auth["body"]["player_id"],
        'playerticket': auth["body"]["player_ticket"],
        'protoversion': '1',
        'sdkversion': '0.19.1.1139',
        'sessionid': auth["body"]["session_id"],
        'titleid': '4njtt',
        'titleregionid': 'awsnaor_4njtt_237',
        'uicinfo': '{"PlayerProfile_SetMyName_display_name":{"account_info":{"account":"' + auth["body"]["player_id"] + '","area_id":1001,"plat_id":3,"role_id":"","role_level":1,"role_name":" ","role_pic_url":"","user_desc":"","user_sign":"","world_id":0},"extra":"{\\r\\n}","scene_id":101}}',
        'seq': '10025',
        'content-type': 'application/json;charset=UTF-8',
    }, json={
        "data": {
            "display_name": email.split("@")[0] + str(ts),
            "avatar_uri": "{\"avatarImageName\":\"0\",\"avatarFrameName\":\"0\"}",
        }
    }, **cool)

    nitro = None

    for _ in range(0, 1000):
        # this is repeated for testing purposes - i was debugging packets in the game and wanted to see when the nitro got unlocked
        try:
            print("requesting nitrooooooooo")
            nitro = tecentIntl(
                "/intl/mgw/invoke",
                json.dumps({"area_id": 0, "plat_id": 0, "region": "en"}),
                host="aws-na-vas", # https://test-vas.intlgame.com/',
                replace_params={
                    "gameid": urlParams["gameid"],
                    "ts": int(time.time()),
                    "os": urlParams["os"],
                    "channelid": urlParams["channelid"],
                    "openid": openid,
                    "token": token,
                    "lang_type": urlParams["lang_type"],
                    "r": "/sopactcgi.a20230703adiscord.a20230703adiscord_interface/Receive",
                    "source": "30"
                },
                sigkey="704bd597023c464f7db94d4146235c2d"
            )
            break
        except Exception as e:
            if "RATELIMIT" in str(e):
                raise e
            else:
                pass

    if not nitro:
        raise Exception("ratelimited in 10 tries")

    callback("https://promos.discord.gg/" + nitro["data"]["code"].replace("-", ""))