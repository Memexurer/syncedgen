# -*- coding: utf-8 -*-

from generate import gen_first, gen_second
import asyncio
import websockets
import json
import random
import re
import string
import ctypes
import traceback
from concurrent.futures import ThreadPoolExecutor
from time import sleep
from threading import Condition, Lock 

total_promos_generated = 0
total_accounts = 0

promo_save_lock = Lock()
account_save_lock = Lock()

account_generation_lock = Lock()
account_generation_cond = Condition(account_generation_lock)
accounts_generated = 0
promos_generated = 0

worker_count = 1
threshold = worker_count * 5
release_threshold = threshold // 2
# this multithreading thing sucks, and was slow as fuck
# but at least it worked, and i didnt want to recode this whole thing to golang (maybe it would help somehow...)

websocket_url = ""
websocket_pass = ""

def update_title():
    threshold_str = ""
    if account_generation_lock.locked():
        threshold_str = f"Locked: {(accounts_generated - promos_generated) - threshold} promos remaining to unlock"
    ctypes.windll.kernel32.SetConsoleTitleW(f"Total promos: {total_promos_generated}; Promo ratio: {(total_promos_generated/total_accounts)*100:.2f}%; Acc: {accounts_generated}/{threshold}; Prom: {promos_generated}; {threshold_str}")
    
def handle_promo(link):
    global promos_generated, total_promos_generated, accounts_generated

    if link is not None:
        promos_generated += 1
        total_promos_generated += 1

    if account_generation_lock.locked():
        diff = accounts_generated - promos_generated 
        if diff < release_threshold:
            accounts_generated = 0
            promos_generated = 0

            print("releasing account generation lock")
            account_generation_cond.notify()
            account_generation_lock.release()

    update_title()

    if link is None:
        return

    promo_save_lock.acquire()
    print("promo generated: " + link)
    with open('promos.txt', 'a') as file:
        file.write(link + "\n")
    promo_save_lock.release()

def handle_account_generation(email):
    account_save_lock.acquire()
    with open('accounts.txt', 'a') as file:
        file.write(email + "\n")
    account_save_lock.release()

def error_handling(method, *args):
    try:
        method(*args)
    except:
        traceback.print_exc()
        handle_promo(None)
        

async def handle_mailbox(pool):
    async with websockets.connect(websocket_url) as websocket:
      await websocket.send(websocket_pass) 

      while True:  
        mail = json.loads(await websocket.recv())
        code =  re.findall('\d{5}', mail["payload"])[0]
        target = mail["target"][0]

        print(target + ": " + code)
        if True: # change
            handle_account_generation(target)

            pool.submit(error_handling, gen_second, target, code, handle_promo)

def mail_1989():
    words = "dongtaiwangziyoumen tiananmen tiananmen falungong lihongzhi free tibet liusitiananmenshijian the tiananmen square protests of 1989 tiananmendatusha the tiananmen square massacre fanyoupaidouzheng the anti-rightist struggle dayuejinzhengce the great leap forward wenhuadageming the great proletarian cultural revolution renquan human rights minyun democratization ziyou freedom duli independence duodangzhi multi-party system taiwan taiwan taiwan formosa zhonghuaminguo republic of china xicang tubote tanggute tibet dalailama dalai lama falungong falun dafa xinjiangweiwuerzizhiqu the xinjiang uyghur autonomous region nuobeierhepingjiang nobel peace prize liuxiaobo liu xiaobo minzhu yanlun sixiang fangong fangeming kangyi yundong saoluan baoluan saorao raoluan kangbao pingfan weiquan shiweiyouxing lihongzhi falundafa dafadizi qiangzhiduanzhong qiangzhiduotai minzujinghua rentishiyan suqing huyaobang zhaoziyang weijingsheng wangdan huanzhengyumin hepingyanbian jiliuzhongguo beijingzhichun dajiyuanshibao jiupinglungongchandang ducai zhuanzhi yazhi tongyi jianshi zhenya pohai qinlve lveduo pohuai kaowen tusha huozhaiqiguan youguai maimairenkou youjin zousi dupin maiyin chunhua dubo liuhecai tiananmen tiananmen falungong lihongzhi winnie the pooh liuxiaobodongtaiwangziyoumen"
    words = words.split(" ")
    word = random.choice(words) +  ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for i in range(12)) 
    return word.replace(" ", "")[:20] + f"@{random.choice(words)[:7]}.grupahakerskapiotr.us"

def do_gen_task():
    for i in range(1): # change
        try:
            global accounts_generated, promos_generated, total_accounts

            if not account_generation_lock.locked() and accounts_generated - promos_generated > threshold:
                print("we generated too many accounts!!!!!! sleeping for now")
                account_generation_lock.acquire()

            while account_generation_lock.locked():
                sleep(1)

            gen_first(mail_1989())
            
            accounts_generated += 1
            total_accounts += 1
            update_title()
        except Exception as e:
            print(e)

async def main():
    with ThreadPoolExecutor(max_workers=None) as pool:
        for _ in range(worker_count):
            pool.submit(do_gen_task)
        
        await asyncio.create_task(handle_mailbox(pool)) 
        
asyncio.run(main())