#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
域名规则转换器 (converter.py)
=====================================
功能: 从domains目录读取域名列表文件，生成多格式规则文件

输入:
  - domains目录下的txt文件，每个文件名为组名
  - 支持格式: AdBlock (||example.com^), Hosts (0.0.0.0 example.com), 纯域名, 带通配符域名、IP地址、IP地址范围

输出格式:
  1. AdBlock格式 (adblock.txt)
     - AdBlock拦截规则格式，以||开头，^结尾
  
  2. Classical格式:
     - classical.yaml - Clash Classical YAML格式
       - 包含文件头(# NAME, # AUTHOR等)
       - 规则格式: DOMAIN-SUFFIX,example.com 或 DOMAIN-KEYWORD,keyword 或 IP-CIDR,192.168.1.0/24
       - 带payload:前缀
     - classical.txt - Clash Classical文本格式
       - 与yaml格式内容相同，但不包含文件头
  
  3. Domain格式:
     - domain.yaml - Domain YAML格式
       - 仅包含域名，不包含IP地址
       - 格式: payload: - '.example.com'
     - domain.txt - Domain文本格式
       - 仅包含域名，每行一个，格式: .example.com
  
  4. IPCIDR格式:
     - ipcidr.yaml - IPCIDR YAML格式
       - 仅包含IP地址和CIDR范围
       - 格式: payload: - '192.168.1.0/24'
     - ipcidr.txt - IPCIDR文本格式
       - 仅包含IP地址和CIDR范围，每行一个

输出目录:
  - rules/<组名>/

使用方法:
  python3 converter.py

注意事项:
  - 仅处理domains目录下的.txt文件
  - 自动去重和去除子域名
  - 并行处理提高效率
"""

# 基础导入
import re
import time
import datetime
import logging
import sys
from pathlib import Path
from typing import List, Set, Dict, Optional, Tuple, Iterator
import os

# 设置时区为中国标准时间
os.environ['TZ'] = 'Asia/Shanghai'
time.tzset()

# 并发处理
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial
import multiprocessing as mp

# 配置日志系统
logging.basicConfig(
    level=logging.INFO,                # 日志级别设置为INFO
    format='%(asctime)s - %(levelname)s - %(message)s',  # 日志格式：时间-级别-消息
    handlers=[logging.StreamHandler()]  # 输出到控制台
)
logger = logging.getLogger(__name__)  # 创建日志记录器实例

# 配置参数
WORKERS = mp.cpu_count()  # 使用CPU核心数作为工作线程数
RULEGROUP_WORKERS = 8     # 文件处理的最大并行数


# 本地文件配置
DOMAINS_DIR = Path("domains")


# 移除黑白名单配置，直接使用domains目录下的所有文件

def log_info(message: str) -> None:
    """
    记录信息级别日志
    
    参数:
        message: 要记录的日志消息
    """
    logger.info(message)

def log_error(message: str) -> None:
    """
    记录错误级别日志
    
    参数:
        message: 要记录的日志消息
    """
    logger.error(message)

def sanitize(name: str) -> Optional[str]:
    """
    清理组名，将其转换为安全的文件名格式
    
    参数:
        name: 原始组名
    
    返回:
        清理后的组名，保留字母、数字、中文、下划线、连字符和点号，其他字符替换为下划线
    """
    if not name:
        return None
    # 保留字母、数字、中文和部分符号，替换其他为下划线
    return re.sub(r'[^\w\u4e00-\u9fa5\-_\.]', '_', name).strip('_')

def read_local_file(file_path: str) -> List[str]:
    """
    读取本地文件内容并返回非空行列表
    
    参数:
        file_path: 文件路径
    
    返回:
        文件中的非空行列表，已去除行尾换行符
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return [line.rstrip('\n') for line in f if line.strip()]
    except Exception as e:
        log_error(f"读取文件失败 {file_path}: {e}", critical=True)
        return []

def read_all_files(file_paths: List[str]) -> Dict[str, List[str]]:
    """
    并行读取多个本地文件的内容
    
    参数:
        file_paths: 文件路径列表
    
    返回:
        以文件路径为键，文件内容(非空行列表)为值的字典
    """
    if not file_paths:
        return {}
    
    results = {}
    with ThreadPoolExecutor(max_workers=WORKERS) as executor:
        future_to_file = {executor.submit(read_local_file, file_path): file_path for file_path in file_paths}
        for future in as_completed(future_to_file):
            file_path = future_to_file[future]
            try:
                content = future.result()
                results[file_path] = content
                log_info(f"读取完成: {file_path} ({len(content)}行)")
            except Exception as e:
                log_error(f"读取异常: {file_path} - {str(e)[:100]}", critical=True)
    
    return results

def extract_domain(line: str) -> Optional[str]:
    """
    从规则行中提取域名或IP地址
    
    参数:
        line: 规则行字符串
    
    返回:
        提取的域名(小写)或IP地址/IP-CIDR字符串，如果无法提取则返回None
        
    支持的规则格式:
        - AdBlock: ||example.com^
        - Hosts: 0.0.0.0 example.com
        - 纯域名: example.com
        - 带通配符的域名: *.example.com
        - IP地址: 127.0.0.1
        - IP-CIDR范围: 127.0.0.0/8
    """
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    
    # 匹配IP-CIDR格式: 127.0.0.0/8
    ip_cidr_pattern = r'^(\d+\.\d+\.\d+\.\d+(?:/\d+)?)$'
    ip_cidr_match = re.match(ip_cidr_pattern, line)
    if ip_cidr_match:
        return ip_cidr_match.group(1)
    
    # 匹配各种规则格式的正则表达式
    patterns = [
        # AdBlock格式: ||example.com^ (双竖线开头，域名，^结尾)
        r'^\|\|([\w\-\.]+)\^',
        # Hosts格式: 0.0.0.0 example.com (IP地址+空格+域名)
        r'^\d+\.\d+\.\d+\.\d+\s+([\w\-\.]+)',
        # 纯域名格式: example.com
        r'^([\w\-\.]+)$',
        # 带通配符的域名: *.example.com
        r'^\*\.([\w\-\.]+)$',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, line)
        if match:
            return match.group(1).lower()
    
    return None



def extract_domains(lines: List[str], extract_func) -> Set[str]:
    """
    使用指定的提取函数从行列表中提取所有域名
    
    参数:
        lines: 规则行列表
        extract_func: 域名提取函数
    
    返回:
        提取的唯一域名集合
    """
    domains = set()
    for line in lines:
        domain = extract_func(line)
        if domain:
            domains.add(domain)
    return domains

def parallel_extract_domains(lines: List[str], extract_func) -> Set[str]:
    """
    并行从行列表中提取域名，提高处理效率
    
    参数:
        lines: 规则行列表
        extract_func: 域名提取函数
    
    返回:
        提取的唯一域名集合
    """
    if not lines:
        return set()
    
    # 计算分块大小，确保每个块至少有1行
    chunk_size = max(1, len(lines) // WORKERS)
    # 将行列表分块，用于并行处理
    chunks = [lines[i:i+chunk_size] for i in range(0, len(lines), chunk_size)]
    
    with mp.Pool(WORKERS) as pool:
        results = pool.map(partial(extract_domains, extract_func=extract_func), chunks)
    
    return set.union(*results)

def get_parent_domains(domain: str) -> List[str]:
    """
    获取域名的所有父域名（不包括顶级域名和完整域名本身）
    
    参数:
        domain: 完整域名字符串
    
    返回:
        父域名列表，例如: example.com -> [example.com] 不返回
        sub.example.com -> [example.com]
    """
    parts = domain.split('.')
    parents = []
    for i in range(1, len(parts) - 1):  # 至少保留二级域名
        parents.append('.'.join(parts[i:]))
    return parents

def remove_subdomains(domains: Set[str]) -> Set[str]:
    """
    移除子域名，仅保留父域名（AdBlock规则语义）
    
    参数:
        domains: 域名集合
    
    返回:
        去重后的域名集合，仅包含父域名
        
    说明:
        如果存在example.com和sub.example.com，仅保留example.com
    """
    if not domains:
        return set()
    
    sorted_domains = sorted(domains, key=lambda x: (x.count('.'), x))  # 父域名先处理
    keep = set()
    
    for domain in sorted_domains:
        if not any(parent in keep for parent in get_parent_domains(domain)):
            keep.add(domain)
    
    log_info(f"去重: 输入{len(domains)} → 输出{len(keep)}")
    return keep



def save_domains_to_files(domains: Set[str], output_path: Path, group_name: str) -> None:
    """
    将域名保存为多种格式的文件
    
    参数:
        domains: 域名集合，包含域名、IP地址和CIDR范围
        output_path: 输出目录路径
        group_name: 组名（文件名前缀）
    
    输出文件:
        1. adblock.txt - AdBlock格式
        2. classical.yaml - Clash Classical格式YAML
        3. classical.txt - Clash Classical格式文本
        4. domain.yaml - Domain格式YAML
        5. domain.txt - Domain格式文本
        6. ipcidr.yaml - IPCIDR格式YAML
        7. ipcidr.txt - IPCIDR格式文本
    
    处理逻辑:
        - 将输入的域名集合按类型分类: IP地址/CIDR范围、完整域名、关键词
        - IP地址/CIDR范围: 输出到Classical和IPCIDR格式文件
        - 完整域名: 输出到所有格式文件
        - 关键词: 输出到所有格式文件
        - IPCIDR格式文件仅在存在IP地址/CIDR范围时生成
        - 所有输出文件包含标准注释头: NAME, AUTHOR, TYPE, UPDATED, TOTAL
    """
    if not domains:
        log_error(f"无域名保存: {output_path}")
        return
    
    sorted_domains = sorted(domains)
    group_dir = output_path / group_name
    group_dir.mkdir(parents=True, exist_ok=True)
    
    # 使用当前时间作为更新时间（中国标准时间）
    # 中国标准时间比UTC时间快8小时
    current_time = (datetime.datetime.utcnow() + datetime.timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S CST")
    
    # 保存AdBlock格式
    adblock_path = group_dir / "adblock.txt"
    with open(adblock_path, "w", encoding="utf-8") as f:
        # 添加注释头
        f.write(f"# NAME: {group_name}\n")
        f.write("# AUTHOR: believems\n")
        f.write("# TYPE: adblock\n")
        f.write(f"# UPDATED: {current_time}\n")
        f.write(f"# TOTAL: {len(sorted_domains)}\n")
        # 写入规则内容
        f.write('\n'.join(f"||{d}^" for d in sorted_domains))
    log_info(f"保存AdBlock: {adblock_path} ({len(sorted_domains)}域名)")
    
    # 统计DOMAIN-KEYWORD和DOMAIN-SUFFIX的数量
    domain_keyword_count = 0
    domain_suffix_count = 0
    classical_lines = []
    classical_yaml_lines = []
    domain_lines = []
    domain_yaml_lines = []
    # IPCIDR格式专用列表，仅存储IP地址和CIDR范围
    ipcidr_lines = []
    ipcidr_yaml_lines = []
    
    for d in sorted_domains:
        # 使用正则表达式检测是否为IP地址或CIDR范围
        # 匹配格式: 192.168.1.1 或 192.168.1.0/24
        is_ip_or_cidr = bool(re.match(r'^\d+\.\d+\.\d+\.\d+(?:/\d+)?$', d))
        
        if is_ip_or_cidr:
            # IP地址或CIDR范围处理
            # 添加到Classical格式
            classical_lines.append(f"IP-CIDR,{d}")
            classical_yaml_lines.append(f"  - IP-CIDR,{d}")
            # IP地址不计入Domain统计
            domain_suffix_count += 1
            # 添加到IPCIDR格式专用列表
            ipcidr_lines.append(f"{d}")
            ipcidr_yaml_lines.append(f"  - '{d}'")
        elif '.' in d:
            # 包含点号的是完整域名，使用DOMAIN-SUFFIX
            classical_lines.append(f"DOMAIN-SUFFIX,{d}")
            classical_yaml_lines.append(f"  - DOMAIN-SUFFIX,{d}")
            domain_lines.append(f".{d}")
            domain_yaml_lines.append(f"  - '.{d}'")
            domain_suffix_count += 1
        else:
            # 不包含点号的是关键词，使用DOMAIN-KEYWORD
            classical_lines.append(f"DOMAIN-KEYWORD,{d}")
            classical_yaml_lines.append(f"  - DOMAIN-KEYWORD,{d}")
            # 关键词在domain格式中直接使用
            domain_lines.append(f"{d}")
            domain_yaml_lines.append(f"  - '{d}'")
            domain_keyword_count += 1
    
    total_count = domain_keyword_count + domain_suffix_count
    
    # 保存Classical YAML格式（原clash.yaml）
    classical_yaml_path = group_dir / "classical.yaml"
    with open(classical_yaml_path, "w", encoding="utf-8") as f:
        # 添加自定义文件头，NAME使用文件名（无后缀）
        f.write(f"# NAME: {group_name}\n")
        f.write("# AUTHOR: believems\n")
        f.write("# TYPE: classical\n")
        f.write(f"# UPDATED: {current_time}\n")
        f.write(f"# DOMAIN-KEYWORD: {domain_keyword_count}\n")
        f.write(f"# DOMAIN-SUFFIX: {domain_suffix_count}\n")
        f.write(f"# TOTAL: {total_count}\n")
        # 写入payload内容
        f.write("payload:\n")
        f.write('\n'.join(classical_yaml_lines))
    log_info(f"保存Classical YAML: {classical_yaml_path} ({len(sorted_domains)}域名)")
    
    # 保存Classical TXT格式
    classical_txt_path = group_dir / "classical.txt"
    with open(classical_txt_path, "w", encoding="utf-8") as f:
        # 添加注释头
        f.write(f"# NAME: {group_name}\n")
        f.write("# AUTHOR: believems\n")
        f.write("# TYPE: classical\n")
        f.write(f"# UPDATED: {current_time}\n")
        f.write(f"# DOMAIN-KEYWORD: {domain_keyword_count}\n")
        f.write(f"# DOMAIN-SUFFIX: {domain_suffix_count}\n")
        f.write(f"# TOTAL: {total_count}\n")
        # 写入规则内容
        f.write('\n'.join(classical_lines))
    log_info(f"保存Classical TXT: {classical_txt_path} ({len(sorted_domains)}域名)")
    
    # 保存Domain YAML格式
    domain_yaml_path = group_dir / "domain.yaml"
    with open(domain_yaml_path, "w", encoding="utf-8") as f:
        # 添加自定义文件头
        f.write(f"# NAME: {group_name}\n")
        f.write("# AUTHOR: believems\n")
        f.write("# TYPE: domain\n")
        f.write(f"# UPDATED: {current_time}\n")
        f.write(f"# TOTAL: {total_count}\n")
        # 写入payload内容
        f.write("payload:\n")
        f.write('\n'.join(domain_yaml_lines))
    log_info(f"保存Domain YAML: {domain_yaml_path} ({len(sorted_domains)}域名)")
    
    # 保存Domain TXT格式
    domain_txt_path = group_dir / "domain.txt"
    with open(domain_txt_path, "w", encoding="utf-8") as f:
        # 添加注释头
        f.write(f"# NAME: {group_name}\n")
        f.write("# AUTHOR: believems\n")
        f.write("# TYPE: domain\n")
        f.write(f"# UPDATED: {current_time}\n")
        f.write(f"# TOTAL: {total_count}\n")
        # 写入规则内容
        f.write('\n'.join(domain_lines))
    log_info(f"保存Domain TXT: {domain_txt_path} ({len(sorted_domains)}域名)")
    
    # 保存IPCIDR YAML格式
    if ipcidr_lines:
        ipcidr_yaml_path = group_dir / "ipcidr.yaml"
        with open(ipcidr_yaml_path, "w", encoding="utf-8") as f:
            # 添加自定义文件头
            f.write(f"# NAME: {group_name}\n")
            f.write("# AUTHOR: believems\n")
            f.write("# TYPE: ipcidr\n")
            f.write(f"# UPDATED: {current_time}\n")
            f.write(f"# TOTAL: {len(ipcidr_lines)}\n")
            # 写入payload内容
            f.write("payload:\n")
            f.write('\n'.join(ipcidr_yaml_lines))
        log_info(f"保存IPCIDR YAML: {ipcidr_yaml_path} ({len(ipcidr_lines)}条目)")
    
    # 保存IPCIDR TXT格式
    if ipcidr_lines:
        ipcidr_txt_path = group_dir / "ipcidr.txt"
        with open(ipcidr_txt_path, "w", encoding="utf-8") as f:
            # 添加注释头
            f.write(f"# NAME: {group_name}\n")
            f.write("# AUTHOR: believems\n")
            f.write("# TYPE: ipcidr\n")
            f.write(f"# UPDATED: {current_time}\n")
            f.write(f"# TOTAL: {len(ipcidr_lines)}\n")
            # 写入规则内容
            f.write('\n'.join(ipcidr_lines))
        log_info(f"保存IPCIDR TXT: {ipcidr_txt_path} ({len(ipcidr_lines)}条目)")

def process_domain_rules(lines: List[str]) -> Set[str]:
    """
    处理域名规则，并行提取域名
    
    参数:
        lines: 规则行列表
    
    返回:
        提取的域名集合
    """
    return parallel_extract_domains(lines, extract_domain)

def process_rule_group(name: str, files: List[str], read_files: Dict[str, List[str]], output_dir: Path) -> None:
    """
    处理单个规则组（文件）
    
    参数:
        name: 规则组名称
        files: 文件路径列表
        read_files: 已读取的文件内容字典
        output_dir: 输出目录路径
    """
    sanitized = sanitize(name)
    if not sanitized or not files:
        log_error(f"无效文件: {name}", critical=True)
        return
    
    log_info(f"处理文件: {name}")
    
    # 收集所有行
    lines = set()
    for file_path in files:
        lines.update(read_files.get(file_path, []))
    
    if not lines:
        log_info(f"文件{name}无内容，跳过")
        return
    
    # 提取并处理域名
    domains = process_domain_rules(list(lines))  # 提取域名
    deduped_domains = remove_subdomains(domains)    # 去重（移除子域名）
    
    # 保存结果
    save_domains_to_files(deduped_domains, output_dir, sanitized)

def main():
    """
    程序主函数，协调整个处理流程
    
    流程:
        1. 创建输出目录
        2. 检查domains目录是否存在
        3. 获取domains目录下的所有txt文件
        4. 并行读取所有文件内容
        5. 并行处理每个文件，生成各种格式的规则文件
    """
    start_time = time.time()
    
    # 创建输出目录
    output_dir = Path("rules")
    output_dir.mkdir(parents=True, exist_ok=True)
    log_info(f"输出目录: {output_dir.absolute()}")
    
    # 检查domains目录是否存在
    if not DOMAINS_DIR.exists():
        log_error(f"domains目录不存在: {DOMAINS_DIR.absolute()}", critical=True)
        return
    
    # 获取domains目录下的所有txt文件
    txt_files = list(DOMAINS_DIR.glob("*.txt"))
    if not txt_files:
        log_error("domains目录下没有txt文件", critical=True)
        return
    
    # 并行读取所有文件
    file_paths = [str(file) for file in txt_files]
    read_files = read_all_files(file_paths)
    
    # 并行处理每个文件
    with ThreadPoolExecutor(max_workers=RULEGROUP_WORKERS) as executor:
        futures = []
        for file in txt_files:
            # 使用文件名（不带后缀）作为组名
            group_name = file.stem
            file_path = str(file)
            futures.append(executor.submit(
                process_rule_group, group_name, [file_path], read_files, output_dir
            ))
        
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                log_error(f"文件处理异常: {str(e)[:100]}")
    
    log_info(f"所有处理完成，总耗时{time.time() - start_time:.2f}s")

if __name__ == "__main__":
    if mp.get_start_method(allow_none=True) != 'spawn' and sys.platform.startswith('win32'):
        mp.set_start_method('spawn')
    try:
        main()
    except KeyboardInterrupt:
        log_error("用户中断")
        sys.exit(1)
    except Exception as e:
        log_error(f"程序终止: {str(e)[:100]}")
        sys.exit(1)