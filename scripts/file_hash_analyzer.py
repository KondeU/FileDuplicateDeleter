#!/usr/bin/env python3
"""
文件哈希分析器 (File Hash Analyzer)
===================================
扫描指定文件夹及子文件夹下的所有文件，计算 MD5 和 SHA256 哈希值，
输出完整哈希表，并筛选出重复文件生成报告。

关于"MD5+SHA256 双重匹配是否足够"的问题：
-----------------------------------------
从实用角度来说，MD5 和 SHA256 同时碰撞的概率极低：
  - MD5 碰撞概率：约 1/2^64（生日攻击），但已知存在人为构造的碰撞
  - SHA256 碰撞概率：约 1/2^128（生日攻击），目前无已知碰撞
  - 两者同时碰撞的概率：约 1/2^192，在可预见的未来完全不可行
因此，MD5+SHA256 双重匹配作为"疑似重复"的判定标准是充分的。

但为了绝对安全，本脚本在生成报告时标注为"疑似重复"，建议配合
file_duplicate_deleter.py 中的逐字节验证来最终确认。

用法:
  python file_hash_analyzer.py <文件夹路径> [--output <输出目录>]

输出文件:
  1. file_hashes.csv        - 完整哈希表（文件路径、MD5、SHA256）
  2. duplicate_report.csv   - 重复文件报告（MD5、SHA256、重复文件路径们）
  3. summary.txt            - 分析摘要
"""

import argparse
import csv
import hashlib
import os
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional


def compute_file_hashes(filepath: str, chunk_size: int = 8192) -> Optional[tuple[str, str]]:
    """
    计算单个文件的 MD5 和 SHA256 哈希值。
    
    Args:
        filepath: 文件完整路径
        chunk_size: 读取块大小（字节），默认 8KB
    
    Returns:
        (md5_hex, sha256_hex) 元组，如果文件无法读取则返回 None
    """
    md5_hasher = hashlib.md5()
    sha256_hasher = hashlib.sha256()
    
    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                md5_hasher.update(chunk)
                sha256_hasher.update(chunk)
        return md5_hasher.hexdigest(), sha256_hasher.hexdigest()
    except (PermissionError, OSError, IOError) as e:
        print(f"  [警告] 无法读取文件: {filepath} ({e})", file=sys.stderr)
        return None


def scan_directory(root_dir: str) -> list[dict]:
    """
    扫描目录及其子目录下的所有文件，计算哈希值。
    
    Args:
        root_dir: 根目录路径
    
    Returns:
        文件信息字典列表，每个字典包含 path, md5, sha256, size, mtime
    """
    root_path = Path(root_dir).resolve()
    
    if not root_path.exists():
        print(f"错误: 路径不存在 - {root_path}", file=sys.stderr)
        sys.exit(1)
    
    if not root_path.is_dir():
        print(f"错误: 路径不是目录 - {root_path}", file=sys.stderr)
        sys.exit(1)
    
    files_info = []
    total_files = 0
    skipped_files = 0
    error_files = 0
    
    print(f"正在扫描目录: {root_path}")
    print("-" * 60)
    
    # 首先统计文件总数
    all_files = []
    for dirpath, dirnames, filenames in os.walk(root_path):
        # 跳过没有读取权限的目录
        try:
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                all_files.append(filepath)
        except PermissionError:
            print(f"  [警告] 无权限访问目录: {dirpath}", file=sys.stderr)
            continue
    
    total_files = len(all_files)
    print(f"发现 {total_files} 个文件，正在计算哈希值...")
    print()
    
    start_time = time.time()
    
    for i, filepath in enumerate(all_files, 1):
        # 跳过符号链接
        if os.path.islink(filepath):
            skipped_files += 1
            continue
        
        try:
            file_size = os.path.getsize(filepath)
            mtime = os.path.getmtime(filepath)
        except OSError:
            error_files += 1
            continue
        
        # 显示进度
        progress = i / total_files * 100
        bar_len = 40
        filled = int(bar_len * i / total_files)
        bar = "█" * filled + "░" * (bar_len - filled)
        elapsed = time.time() - start_time
        if i > 0:
            eta = elapsed / i * (total_files - i)
            eta_str = f"{int(eta // 60)}m{int(eta % 60)}s"
        else:
            eta_str = "计算中..."
        
        sys.stdout.write(
            f"\r  进度: [{bar}] {progress:.1f}% "
            f"({i}/{total_files}) "
            f"已用时: {int(elapsed // 60)}m{int(elapsed % 60)}s "
            f"剩余: {eta_str}"
        )
        sys.stdout.flush()
        
        result = compute_file_hashes(filepath)
        if result is None:
            error_files += 1
            continue
        
        md5_hex, sha256_hex = result
        files_info.append({
            "path": filepath,
            "md5": md5_hex,
            "sha256": sha256_hex,
            "size": file_size,
            "mtime": mtime,
        })
    
    elapsed = time.time() - start_time
    print(f"\n\n扫描完成！总用时: {int(elapsed // 60)}分{int(elapsed % 60)}秒")
    print(f"  成功处理: {len(files_info)} 个文件")
    print(f"  跳过(符号链接): {skipped_files} 个")
    print(f"  出错: {error_files} 个")
    
    return files_info


def find_duplicates(files_info: list[dict]) -> list[dict]:
    """
    根据哈希值找出重复文件。
    
    判定标准：MD5 和 SHA256 均相同的文件视为疑似重复。
    
    Args:
        files_info: 文件信息列表
    
    Returns:
        重复文件报告列表
    """
    # 按 (md5, sha256) 分组
    hash_groups = defaultdict(list)
    for info in files_info:
        key = (info["md5"], info["sha256"])
        hash_groups[key].append(info)
    
    # 筛选出有多个文件的组
    duplicates = []
    for (md5, sha256), group in hash_groups.items():
        if len(group) > 1:
            file_size = group[0]["size"]
            dup_entry = {
                "md5": md5,
                "sha256": sha256,
                "size": file_size,
                "count": len(group),
                "files": [f["path"] for f in group],
                "mtimes": [f["mtime"] for f in group],
            }
            duplicates.append(dup_entry)
    
    # 按重复数量降序排列
    duplicates.sort(key=lambda x: x["count"], reverse=True)
    
    return duplicates


def save_hash_table(files_info: list[dict], output_dir: str) -> str:
    """
    保存完整哈希表为 CSV 文件。
    """
    output_path = os.path.join(output_dir, "file_hashes.csv")
    
    with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["文件完整路径", "MD5哈希", "SHA256哈希", "文件大小(字节)", "修改时间"])
        
        for info in sorted(files_info, key=lambda x: x["path"]):
            mtime_str = datetime.fromtimestamp(info["mtime"]).strftime("%Y-%m-%d %H:%M:%S")
            writer.writerow([
                info["path"],
                info["md5"],
                info["sha256"],
                info["size"],
                mtime_str,
            ])
    
    return output_path


def save_duplicate_report(duplicates: list[dict], output_dir: str) -> str:
    """
    保存重复文件报告为 CSV 文件。
    """
    output_path = os.path.join(output_dir, "duplicate_report.csv")
    
    # 计算最大重复数量，决定列数
    max_count = max((d["count"] for d in duplicates), default=0)
    
    with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        
        # 表头
        header = ["MD5哈希", "SHA256哈希", "文件大小(字节)", "重复数量"]
        for i in range(1, max_count + 1):
            header.append(f"重复文件路径_{i}")
            header.append(f"文件修改时间_{i}")
        writer.writerow(header)
        
        for dup in duplicates:
            row = [dup["md5"], dup["sha256"], dup["size"], dup["count"]]
            for j in range(max_count):
                if j < len(dup["files"]):
                    row.append(dup["files"][j])
                    mtime_str = datetime.fromtimestamp(dup["mtimes"][j]).strftime("%Y-%m-%d %H:%M:%S")
                    row.append(mtime_str)
                else:
                    row.append("")
                    row.append("")
            writer.writerow(row)
    
    return output_path


def format_size(size_bytes: float) -> str:
    """将字节数格式化为可读字符串。"""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} PB"


def save_root_path(root_dir: str, output_dir: str) -> str:
    """
    保存扫描根目录路径到 CSV 文件。
    
    Args:
        root_dir: 扫描的根目录路径
        output_dir: 输出目录路径
    
    Returns:
        保存的文件路径
    """
    output_path = os.path.join(output_dir, "root_path.csv")
    
    with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["扫描根目录"])
        writer.writerow([root_dir])
    
    return output_path


def save_summary(
    files_info: list[dict],
    duplicates: list[dict],
    output_dir: str,
    hash_table_path: str,
    report_path: str,
) -> str:
    """
    保存分析摘要。
    """
    output_path = os.path.join(output_dir, "summary.txt")
    
    total_files = len(files_info)
    total_size = sum(f["size"] for f in files_info)
    duplicate_groups = len(duplicates)
    duplicate_files = sum(d["count"] for d in duplicates)
    # 可节省空间 = 重复文件总大小 - 每组保留一份的大小
    saveable_size = sum(d["size"] * (d["count"] - 1) for d in duplicates)
    
    # 唯一文件数（不重复的）
    unique_files = total_files - duplicate_files + duplicate_groups
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("           文件哈希分析报告 (File Hash Analysis Report)\n")
        f.write("=" * 70 + "\n")
        f.write(f"  生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("\n")
        
        f.write("─" * 70 + "\n")
        f.write("  总体统计\n")
        f.write("─" * 70 + "\n")
        f.write(f"  扫描文件总数:        {total_files}\n")
        f.write(f"  唯一文件数:          {unique_files}\n")
        f.write(f"  重复文件组数:        {duplicate_groups}\n")
        f.write(f"  涉及重复的文件数:    {duplicate_files}\n")
        f.write(f"  文件总大小:          {format_size(total_size)}\n")
        f.write(f"  可释放空间(去重后):  {format_size(saveable_size)}\n")
        f.write("\n")
        
        f.write("─" * 70 + "\n")
        f.write("  输出文件\n")
        f.write("─" * 70 + "\n")
        f.write(f"  完整哈希表:   {hash_table_path}\n")
        f.write(f"  重复文件报告: {report_path}\n")
        f.write("\n")
        
        if duplicates:
            f.write("─" * 70 + "\n")
            f.write("  重复文件详情 (按重复数量降序)\n")
            f.write("─" * 70 + "\n")
            for i, dup in enumerate(duplicates, 1):
                f.write(f"\n  [{i}] MD5: {dup['md5']}\n")
                f.write(f"      SHA256: {dup['sha256']}\n")
                f.write(f"      文件大小: {format_size(dup['size'])}\n")
                f.write(f"      重复数量: {dup['count']} 份\n")
                f.write(f"      文件列表:\n")
                for j, filepath in enumerate(dup["files"], 1):
                    mtime_str = datetime.fromtimestamp(dup["mtimes"][j - 1]).strftime("%Y-%m-%d %H:%M:%S")
                    f.write(f"        {j}. {filepath}\n")
                    f.write(f"           修改时间: {mtime_str}\n")
        else:
            f.write("─" * 70 + "\n")
            f.write("  未发现重复文件！\n")
            f.write("─" * 70 + "\n")
        
        f.write("\n" + "=" * 70 + "\n")
        f.write("  关于 MD5+SHA256 双重哈希匹配的可靠性说明:\n")
        f.write("=" * 70 + "\n")
        f.write("""
  问：仅凭 MD5 和 SHA256 同时相同，是否足以确认文件完全相同？

  答：从实用角度，答案是"足够充分"：
  
  1. MD5 碰撞概率约为 1/2^64（生日攻击），虽然已知存在人为构造的
     碰撞，但自然发生的概率极低。
  
  2. SHA256 碰撞概率约为 1/2^128（生日攻击），截至目前无任何已知
     的碰撞实例。
  
  3. MD5+SHA256 同时碰撞的概率约为 1/2^192，这在计算上是不可行
     的，远超任何实际安全需求。
  
  因此，当两个文件的 MD5 和 SHA256 完全一致时，它们内容相同的
  可能性极高，作为"疑似重复"的判定标准完全充分。
  
  如需绝对确认，建议配合 file_duplicate_deleter.py 中的逐字节
  验证功能，该脚本在删除前会对疑似重复文件进行完整的二进制比对。
""")
        f.write("=" * 70 + "\n")
    
    return output_path


def main():
    parser = argparse.ArgumentParser(
        description="文件哈希分析器 - 扫描文件并检测重复",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python file_hash_analyzer.py /path/to/folder
  python file_hash_analyzer.py /path/to/folder --output /path/to/output
        """,
    )
    parser.add_argument(
        "directory",
        help="要扫描的文件夹路径",
    )
    parser.add_argument(
        "--output", "-o",
        help="输出目录路径（默认为当前目录下的 output 文件夹）",
        default=None,
    )
    
    args = parser.parse_args()
    
    # 确定输出目录
    if args.output:
        output_dir = args.output
    else:
        output_dir = os.path.join(os.getcwd(), "output")
    
    os.makedirs(output_dir, exist_ok=True)
    
    print("=" * 60)
    print("       文件哈希分析器 (File Hash Analyzer)")
    print("=" * 60)
    print()
    
    # 第一步：扫描并计算哈希
    files_info = scan_directory(args.directory)
    
    if not files_info:
        print("\n未找到任何文件，程序退出。")
        sys.exit(0)
    
    print()
    print("-" * 60)
    print("正在分析重复文件...")
    
    # 第二步：查找重复
    duplicates = find_duplicates(files_info)
    
    # 第三步：保存结果
    print("正在保存结果...")
    
    root_path_file = save_root_path(str(Path(args.directory).resolve()), output_dir)
    hash_table_path = save_hash_table(files_info, output_dir)
    report_path = save_duplicate_report(duplicates, output_dir)
    summary_path = save_summary(files_info, duplicates, output_dir, hash_table_path, report_path)
    
    print()
    print("=" * 60)
    print("  分析完成！")
    print("=" * 60)
    print(f"  扫描根目录:   {root_path_file}")
    print(f"  完整哈希表:   {hash_table_path}")
    print(f"  重复文件报告: {report_path}")
    print(f"  分析摘要:     {summary_path}")
    
    if duplicates:
        total_dup = sum(d["count"] for d in duplicates)
        saveable = sum(d["size"] * (d["count"] - 1) for d in duplicates)
        print()
        print(f"  发现 {len(duplicates)} 组重复文件，涉及 {total_dup} 个文件")
        print(f"  去重后可释放空间: {format_size(saveable)}")
        print()
        print("  如需删除重复文件，请运行:")
        print(f"  python file_duplicate_deleter.py {report_path}")
    else:
        print()
        print("  恭喜！未发现任何重复文件。")


if __name__ == "__main__":
    main()
