import json
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

PROXY = "http://127.0.0.1:7897"

with open('/Users/qiushuanglong/Library/Application Support/Microsoft Edge/Default/Bookmarks') as f:
    d = json.load(f)

bar = d['roots']['bookmark_bar']

active_bookmarks = []
def scan(node, path):
    name = node.get('name', '')
    curr = f'{path} / {name}' if path else name
    if node.get('type') == 'url':
        active_bookmarks.append({
            'id': node.get('id'),
            'name': name,
            'url': node.get('url'),
            'path': curr
        })
    elif node.get('type') == 'folder':
        if name != '网站后台' and not name.startswith('⚠️'):
            for ch in node.get('children', []):
                scan(ch, curr)

for ch in bar.get('children', []):
    if ch.get('type') == 'url':
        active_bookmarks.append({
            'id': ch.get('id'),
            'name': ch.get('name'),
            'url': ch.get('url'),
            'path': '收藏夹栏'
        })
    elif ch.get('type') == 'folder':
        if ch.get('name') != '网站后台' and not ch.get('name').startswith('⚠️'):
            scan(ch, '收藏夹栏')

print(f"Loaded {len(active_bookmarks)} active bookmarks to test.")

ERROR_TITLE_PATTERNS = [
    r'403\s+forbidden',
    r'404\s+not\s+found',
    r'502\s+bad\s+gateway',
    r'500\s+internal\s+server\s+error',
    r'503\s+service\s+temporarily\s+unavailable',
    r'网站未找到',
    r'页面未找到',
    r'站点不存在',
    r'域名出售',
    r'域名停放',
    r'网站正在建设中',
    r'系统维护中',
    r'温馨提示.*(违规|封禁|拦截)'
]

PARKING_KEYWORDS = [
    'nameslink.com', 'sedo.com', 'dan.com', 'hugedomains.com',
    'domain-promo', 'domain_parking', 'parking-land', 'domainmarket.com',
    'bodis.com', 'parkingcrew.net', 'godaddy.com/domainsearch',
    'wanwang.aliyun.com/domain/parking', '域名出售', '买下此域名'
]

def test_url(bm):
    url = bm['url']

    # Step 1: Probe with strict SSL (direct)
    cmd_strict = [
        "curl", "-s", "-S", "-L",
        "--connect-timeout", "4", "--max-time", "6",
        "-A", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        url
    ]
    p_strict = subprocess.run(cmd_strict, capture_output=True)
    body_bytes = p_strict.stdout[:50000]
    err_msg = p_strict.stderr.decode('utf-8', errors='ignore').strip()
    
    # Check if SSL error occurred
    ssl_failed = False
    if 'ssl' in err_msg.lower() or 'certificate' in err_msg.lower():
        ssl_failed = True
        # Try proxy to see if proxy has valid SSL
        cmd_p_strict = [
            "curl", "-s", "-S", "-L",
            "-x", PROXY,
            "--connect-timeout", "5", "--max-time", "8",
            "-A", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            url
        ]
        pp = subprocess.run(cmd_p_strict, capture_output=True)
        if not ('ssl' in pp.stderr.decode('utf-8', errors='ignore').lower()):
            ssl_failed = False
            body_bytes = pp.stdout[:50000]

    if ssl_failed:
        return {
            **bm,
            'abnormal': True,
            'category': '🔒 证书异常_红屏拦截',
            'reason': f'SSL证书不匹配或过期 ({err_msg[:60]})'
        }

    # If body is empty, check headers
    if not body_bytes:
        # Check HTTP status code
        cmd_code = ["curl", "-s", "-k", "-L", "-o", "/dev/null", "-w", "%{http_code}", "--connect-timeout", "4", "--max-time", "6", url]
        p_code = subprocess.run(cmd_code, capture_output=True, text=True)
        code_str = p_code.stdout.strip()
        code = int(code_str) if code_str.isdigit() else 0
        if code == 403 or code == 401:
            return {**bm, 'abnormal': True, 'category': '🚫 访问受限_403/401', 'reason': f'HTTP {code} 拒绝访问'}
        elif code == 404 or code == 410:
            return {**bm, 'abnormal': True, 'category': '🔍 页面丢失_404', 'reason': f'HTTP {code} 页面不存在'}
        elif 500 <= code <= 599:
            return {**bm, 'abnormal': True, 'category': '💥 服务异常_5xx', 'reason': f'HTTP {code} 服务端报错'}
        elif code == 0:
            return {**bm, 'abnormal': True, 'category': '🔌 空响应或连接重置', 'reason': '服务器接收连接但未返回任何数据'}

    # Analyze HTML content
    text = body_bytes.decode('utf-8', errors='ignore')
    if not text:
        text = body_bytes.decode('gbk', errors='ignore')

    # Extract title
    title_match = re.search(r'<title[^>]*>(.*?)</title>', text, re.IGNORECASE | re.DOTALL)
    page_title = title_match.group(1).strip() if title_match else ""

    # Check title error patterns
    for pat in ERROR_TITLE_PATTERNS:
        if re.search(pat, page_title, re.IGNORECASE):
            return {
                **bm,
                'abnormal': True,
                'category': '🚫 伪存活_页面标题为错误',
                'reason': f'网页标题为错误页: <title>{page_title[:40]}</title>'
            }

    # Check domain parking keywords in title or text
    if any(pk in page_title.lower() for pk in PARKING_KEYWORDS) or any(pk in text[:3000].lower() for pk in ['nameslink.com', 'domain-promo', '进行游戏并领取优惠', '此域名正在出售']):
        return {
            **bm,
            'abnormal': True,
            'category': '🏷️ 域名停放_博彩/广告跳转',
            'reason': f'域名停放或广告劫持: {page_title[:40]}'
        }

    return {**bm, 'abnormal': False, 'category': 'NORMAL', 'reason': f'正常浏览 (Title: {page_title[:30]})'}

print("Starting deep health inspection across 339 active bookmarks...")
results = []
with ThreadPoolExecutor(max_workers=20) as executor:
    futures = {executor.submit(test_url, bm): bm for bm in active_bookmarks}
    done = 0
    for f in as_completed(futures):
        res = f.result()
        results.append(res)
        done += 1
        if done % 50 == 0 or done == len(active_bookmarks):
            print(f"Progress: {done}/{len(active_bookmarks)}")

with open('work/abnormal_inspection_results.json', 'w', encoding='utf-8') as f:
    json.dump(results, f, ensure_ascii=False, indent=2)

print("Saved to work/abnormal_inspection_results.json")
