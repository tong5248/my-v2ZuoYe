# -*- coding: utf-8 -*-
import requests
import re
import base64
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
import urllib.parse

# --- 核心配置：模拟 V2Ray 客户端特征 ---
V2RAY_HEADERS = {
    "User-Agent": "v2rayN/6.23",
    "Accept": "*/*",
    "Connection": "keep-alive"
}

# --- 过滤配置 ---
# 仅保留 vless 协议
PROTOCOL_WHITELIST = [
    "vless://",      # 你的核心协议
    "hysteria2://",  # 暴力加速，适合视频
    "hy2://",        # 部分软件对 Hys2 的简写
    "trojan://",     # 稳定伪装，适合长期办公
    "vmess://"       # 兼容性最强
]
# 备注中包含以下词汇的节点将被剔除
KEYWORD_BLACKLIST = ["中国", "香港", "俄罗斯", "未知", "伊朗", "德黑兰", "CN", "HK", "RU", "IR", "回国", "测试", "->"]

# --- 辅助工具 ---
def decode_base64_to_links(raw_text):
    """将抓取的 Base64 或明文内容转为节点列表"""
    raw_text = raw_text.strip()
    if not raw_text or raw_text.startswith('<'): return [] 
    try:
        pd = len(raw_text) % 4
        if pd: raw_text += '=' * (4 - pd)
        decoded = base64.b64decode(raw_text).decode('utf-8')
        return [l.strip() for l in decoded.splitlines() if '://' in l]
    except:
        return [l.strip() for l in raw_text.splitlines() if '://' in l]

def deep_deduplicate(nodes):
    seen_hosts = set()  # 专门记录 地址+端口
    unique_nodes = []
    
    for node in nodes:
        node = node.strip()
        if not node: continue
        
        try:
            # 1. 彻底解析 URL
            # 例如 vless://uuid@1.2.3.4:443?type=ws...#备注
            parsed = urllib.parse.urlparse(node)
            
            # 2. 提取核心：主机名(hostname)和端口(port)
            # 这样不管 UUID 是什么，也不管后面参数怎么变，只要服务器地址一样就去重
            host_info = f"{parsed.hostname}:{parsed.port}"
            
            # 3. 检查是否已经存在
            if host_info not in seen_hosts:
                seen_hosts.add(host_info)
                unique_nodes.append(node)
            else:
                # 可以在日志里打印一下，看看删掉了谁
                # print(f"🚫 过滤掉重复服务器: {host_info}")
                pass
        except:
            # 解析失败的节点（通常是格式坏了），我们也保留，以防万一
            unique_nodes.append(node)
            
    return unique_nodes

def is_clean_node(node_str):
    """节点精选过滤：协议检查 + 关键词黑名单"""
    # 1. 协议白名单
    if not any(node_str.lower().startswith(p) for p in PROTOCOL_WHITELIST):
        return False
    
    # 2. 关键词黑名单检查
    if "#" in node_str:
        remark = node_str.split("#")[-1]
        if any(word in remark for word in KEYWORD_BLACKLIST):
            return False
    return True

# --- 采集源 1: cfmem.com ---
def fetch_cfmem():
    url = "https://www.cfmem.com"
    print(f"📡 探测中: cfmem.com...")
    try:
        res = requests.get(url, headers=V2RAY_HEADERS, timeout=15)
        soup = BeautifulSoup(res.text, 'html.parser')
        latest_tag = soup.find('h2', class_='entry-title')
        if not latest_tag: return []
        post_url = latest_tag.find('a')['href']
        if post_url.startswith('/'): post_url = url + post_url
        post_res = requests.get(post_url, headers=V2RAY_HEADERS, timeout=15)
        return re.findall(r'https?://v2rayse\.com/[^\s<"\']+\.txt', post_res.text)
    except: return []

# --- 采集源 2: mibei77.com ---
def fetch_mibei():
    url = "https://www.mibei77.com"
    print(f"📡 探测中: mibei77.com...")
    try:
        res = requests.get(url, headers=V2RAY_HEADERS, timeout=15)
        soup = BeautifulSoup(res.text, 'html.parser')
        links = [a.get('href') for a in soup.select('h2 a') if "月" in a.get_text() or "日" in a.get_text()]
        if not links: return []
        post_res = requests.get(links[0], headers=V2RAY_HEADERS, timeout=15)
        return re.findall(r'https?://mm\.mibei77\.com/[^\s<"\']+\.txt', post_res.text)
    except: return []

# --- 采集源 3: bestvpn (全量碰撞) ---
def fetch_bestvpn():
    print("📡 探测中: BestVPN (全量碰撞模式)...")
    today = datetime.now()
    all_hits = []
    for i in range(2):
        target_date = today - timedelta(days=i)
        date_str = target_date.strftime("%Y%m%d")
        path_str = target_date.strftime("%Y/%m")
        found = 0
        for sub_id in range(11): 
            test_txt = f"https://node.freeclashnode.com/uploads/{path_str}/{sub_id}-{date_str}.txt"
            try:
                if requests.head(test_txt, headers=V2RAY_HEADERS, timeout=3).status_code == 200:
                    all_hits.append(test_txt)
                    found += 1
                elif found > 0: break
            except: break
        if all_hits: break
    return all_hits

# --- 采集源 4: oneclash.cc ---
def fetch_oneclash():
    url = "https://oneclash.cc"
    print(f"📡 探测中: oneclash.cc...")
    try:
        res = requests.get(url, headers=V2RAY_HEADERS, timeout=15)
        soup = BeautifulSoup(res.text, 'html.parser')
        tag = soup.select_one('.post_def_title h2 a') or soup.select_one('.post_box a.post_def_left')
        if not tag: return []
        post_url = tag['href']
        if post_url.startswith('/'): post_url = url + post_url
        post_res = requests.get(post_url, headers=V2RAY_HEADERS, timeout=15)
        return re.findall(r'https?://oss\.oneclash\.cc/[^\s<"\']+\.txt', post_res.text)
    except: return []

# --- 主逻辑 ---
def main():
    date_str = datetime.now().strftime("%Y%m%d")
    print(f"🚀 开始执行 {date_str} 节点聚合任务...")

    # 1. 探测阶段
    all_txt_links = []
    crawlers = [fetch_cfmem, fetch_mibei, fetch_bestvpn, fetch_oneclash]
    for crawler in crawlers:
        try: all_txt_links.extend(crawler())
        except: pass
    
    unique_txt_links = list(dict.fromkeys([l.strip() for l in all_txt_links if l.strip()]))
    
    if not unique_txt_links:
        print("❌ 未探测到任何有效源链接。")
        return

    print(f"\n✨ 探测完成，发现以下 {len(unique_txt_links)} 个原始链接：")
    for link in unique_txt_links:
        print(f" 🔗 {link}")

    # 保存原始链接文件
    raw_links_filename = f"{date_str}原始txt.txt"
    #with open(raw_links_filename, "w", encoding="utf-8") as f:
       #f.write("\n".join(unique_txt_links))
    print(f"📝 原始链接已记录至: {raw_links_filename}")

    # 2. 抓取阶段
    raw_nodes_pool = []
    print(f"\n📦 开始抓取节点内容...")
    for link in unique_txt_links:
        try:
            resp = requests.get(link, headers=V2RAY_HEADERS, timeout=15)
            if resp.status_code == 200:
                nodes = decode_base64_to_links(resp.text)
                raw_nodes_pool.extend(nodes)
                print(f"✅ 成功提取: {link.split('/')[-1]} (+{len(nodes)})")
        except: pass

    # 3. 深度去重 + 协议过滤
    # 3.1 首先执行深度去重（忽略备注名对比）
    unique_config_nodes = deep_deduplicate(raw_nodes_pool)
    
    # 3.2 执行精选过滤（VLESS白名单 + 关键词黑名单）
    filtered_nodes = [n for n in unique_config_nodes if is_clean_node(n)]

    # 4. 结果导出
    final_sub_filename = f"{date_str}最终内容.txt"
    if filtered_nodes:
        # 导出明文版
        #with open(f"{date_str}明内容.txt", "w", encoding="utf-8") as f:
            #f.write("\n".join(filtered_nodes))
        
        # 导出 Base64 订阅版
        combined_data = "\n".join(filtered_nodes)
        b64_output = base64.b64encode(combined_data.encode('utf-8')).decode('utf-8')
        #with open(final_sub_filename, "w", encoding="utf-8") as f:
            #f.write(b64_output)
        
        # 同时更新 latest.txt 方便固定链接使用
        with open("zuoye.txt", "w", encoding="utf-8") as f:
            f.write(b64_output)

        print("\n" + "="*45)
        print(f"🎉 聚合精选完成！")
        print(f"📊 原始抓取总量: {len(raw_nodes_pool)}")
        print(f"🛡️ 深度去重剩余: {len(unique_config_nodes)}")
        print(f"🧹 过滤后精选数: {len(filtered_nodes)}")
        print(f"🚫 剔除重复/无效节点: {len(raw_nodes_pool) - len(filtered_nodes)} 个")
        print(f"💾 最终订阅文件: {final_sub_filename}")
        print("="*45)
    else:
        print("❌ 过滤后未发现符合条件的精选节点。")

if __name__ == "__main__":
    main()
