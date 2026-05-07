#!/usr/bin/env python3
"""
重复文件删除器 (Duplicate File Deleter)
========================================
读取 file_hash_analyzer.py 生成的 duplicate_report.csv，删除重复文件，
每组仅保留一份副本。

保留策略（按优先级）：
  1. 保留文件修改时间最新的那份
  2. 若文件修改时间相同，保留文件所在文件夹修改时间最新的那份
  3. 若文件夹修改时间也相同，向上查找父级目录的修改时间
  4. 若一直追溯到用户给定的根目录仍无法区分，则让用户手动选择

安全措施：
  - 删除前对每个疑似重复文件进行逐字节二进制比对，确保真正完全一致
  - 仅当字节完全一致时才执行删除
  - 删除操作使用"移动到回收站"模式（如支持）或永久删除（需确认）

用法:
  python file_duplicate_deleter.py <duplicate_report.csv> [--root <原始扫描根目录>] [--mode <delete|recycle|dry-run>]

参数说明:
  duplicate_report.csv  - 由 file_hash_analyzer.py 生成的重复报告文件
  --root               - 原始扫描的根目录（用于追溯文件夹日期时的边界）
  --mode               - 删除模式:
                          recycle  - 移动到回收站（默认，推荐）
                          delete   - 永久删除（需谨慎）
                          dry-run  - 仅模拟，不实际删除
"""

import argparse
import csv
import hashlib
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

# 尝试导入 send2trash（回收站支持），不可用时回退到永久删除
try:
    import send2trash
    HAS_SEND2TRASH = True
except ImportError:
    HAS_SEND2TRASH = False


def format_size(size_bytes: float) -> str:
    """将字节数格式化为可读字符串。"""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} PB"


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
        print(f"    [警告] 无法读取文件: {filepath} ({e})", file=sys.stderr)
        return None


def verify_file_hash(filepath: str, expected_md5: str, expected_sha256: str) -> bool:
    """
    验证文件当前的哈希值是否与报告中的预期哈希一致。

    Args:
        filepath: 文件路径
        expected_md5: 报告中的 MD5 哈希
        expected_sha256: 报告中的 SHA256 哈希

    Returns:
        True 如果哈希一致，否则 False
    """
    result = compute_file_hashes(filepath)
    if result is None:
        return False
    md5, sha256 = result
    return md5 == expected_md5 and sha256 == expected_sha256


def verify_files_identical(file1: str, file2: str) -> bool:
    """
    逐字节比对两个文件，确认是否完全二进制一致。
    
    Args:
        file1: 第一个文件路径
        file2: 第二个文件路径
    
    Returns:
        True 如果两个文件字节完全一致，否则 False
    """
    # 先比较文件大小，大小不同则必然不同
    try:
        size1 = os.path.getsize(file1)
        size2 = os.path.getsize(file2)
        if size1 != size2:
            return False
    except OSError:
        return False
    
    # 逐字节比较
    chunk_size = 65536  # 64KB 块
    try:
        with open(file1, "rb") as f1, open(file2, "rb") as f2:
            while True:
                chunk1 = f1.read(chunk_size)
                chunk2 = f2.read(chunk_size)
                if chunk1 != chunk2:
                    return False
                if not chunk1:  # 两个文件同时读完
                    return True
    except (OSError, IOError):
        return False


def get_dir_mtime(dirpath: str, root_dir: str) -> float:
    """
    获取目录的修改时间。
    如果目录本身的时间戳不足以区分，递归向上查找父级目录。
    
    Args:
        dirpath: 目录路径
        root_dir: 根目录路径（边界，不向上超过此目录）
    
    Returns:
        目录的修改时间戳
    """
    try:
        return os.path.getmtime(dirpath)
    except OSError:
        return 0.0


def get_ancestral_mtime(filepath: str, root_dir: str) -> list[tuple[str, float]]:
    """
    获取文件所在目录到根目录路径上所有目录的修改时间列表。
    
    从文件所在目录开始，依次向上直到根目录。
    
    Args:
        filepath: 文件路径
        root_dir: 根目录路径（边界）
    
    Returns:
        [(目录路径, 修改时间), ...] 列表，从文件所在目录到根目录
    """
    root_path = Path(root_dir).resolve()
    file_path = Path(filepath).resolve()
    parent = file_path.parent
    
    result = []
    while True:
        try:
            mtime = os.path.getmtime(str(parent))
        except OSError:
            mtime = 0.0
        result.append((str(parent), mtime))
        
        if parent == root_path or parent.parent == parent:
            break
        parent = parent.parent
    
    return result


def select_file_to_keep(
    files: list[str],
    mtimes: list[float],
    root_dir: str,
    file_md5: str = "",
    file_sha256: str = "",
) -> tuple[int, str]:
    """
    根据保留策略选择要保留的文件。

    策略优先级：
    1. 文件修改时间最新的
    2. 文件所在文件夹修改时间最新的
    3. 向上追溯父级目录修改时间
    4. 全部一致时让用户选择

    Args:
        files: 文件路径列表
        mtimes: 对应的文件修改时间列表
        root_dir: 原始扫描根目录
        file_md5: 文件组的 MD5 哈希（用于用户选择提示）
        file_sha256: 文件组的 SHA256 哈希（用于用户选择提示）

    Returns:
        (保留文件的索引, 选择原因说明)
    """
    n = len(files)
    if n == 0:
        return -1, "无文件可选"
    if n == 1:
        return 0, "唯一文件，自动保留"
    
    # === 策略 1：按文件修改时间选择最新的 ===
    max_mtime = max(mtimes)
    candidates = [i for i in range(n) if mtimes[i] == max_mtime]
    
    if len(candidates) == 1:
        mtime_str = datetime.fromtimestamp(max_mtime).strftime("%Y-%m-%d %H:%M:%S")
        return candidates[0], f"文件修改时间最新 ({mtime_str})"
    
    # === 策略 2：按文件所在文件夹修改时间选择最新的 ===
    dir_mtimes = []
    for i in candidates:
        file_dir = str(Path(files[i]).resolve().parent)
        try:
            dmtime = os.path.getmtime(file_dir)
        except OSError:
            dmtime = 0.0
        dir_mtimes.append((i, dmtime))
    
    max_dir_mtime = max(dm[1] for dm in dir_mtimes)
    candidates = [dm[0] for dm in dir_mtimes if dm[1] == max_dir_mtime]
    
    if len(candidates) == 1:
        mtime_str = datetime.fromtimestamp(max_dir_mtime).strftime("%Y-%m-%d %H:%M:%S")
        return candidates[0], f"文件修改时间相同，文件夹修改时间最新 ({mtime_str})"
    
    # === 策略 3：向上追溯父级目录修改时间 ===
    root_path = Path(root_dir).resolve()
    
    # 获取每个候选文件的祖先目录时间线
    ancestral_mtimes = {}
    for i in candidates:
        ancestral_mtimes[i] = get_ancestral_mtime(files[i], root_dir)
    
    # 逐级比较（从最接近文件的目录开始）
    max_depth = max(len(v) for v in ancestral_mtimes.values())
    
    for depth in range(max_depth):
        level_mtimes = []
        for i in candidates:
            if depth < len(ancestral_mtimes[i]):
                level_mtimes.append((i, ancestral_mtimes[i][depth][1]))
            else:
                level_mtimes.append((i, 0.0))
        
        max_level_mtime = max(lm[1] for lm in level_mtimes)
        new_candidates = [lm[0] for lm in level_mtimes if lm[1] == max_level_mtime]
        
        if len(new_candidates) == 1:
            dir_path = ancestral_mtimes[new_candidates[0]][depth][0]
            mtime_str = datetime.fromtimestamp(max_level_mtime).strftime("%Y-%m-%d %H:%M:%S")
            return new_candidates[0], (
                f"追溯至目录 '{dir_path}' 修改时间最新 ({mtime_str})"
            )
        
        candidates = new_candidates
    
    # === 策略 4：所有策略均无法区分，让用户选择 ===
    print()
    print("=" * 60)
    print("  无法自动决定保留哪个文件，请手动选择：")
    print("=" * 60)
    print(f"  MD5:    {file_md5}")
    print(f"  SHA256: {file_sha256}")
    print()
    
    for i, idx in enumerate(candidates):
        filepath = files[idx]
        mtime_str = datetime.fromtimestamp(mtimes[idx]).strftime("%Y-%m-%d %H:%M:%S")
        file_size = format_size(os.path.getsize(filepath)) if os.path.exists(filepath) else "N/A"
        print(f"  [{i + 1}] {filepath}")
        print(f"      修改时间: {mtime_str}  大小: {file_size}")
    
    while True:
        try:
            choice = input(f"\n  请输入要保留的文件编号 (1-{len(candidates)}): ").strip()
            choice_idx = int(choice) - 1
            if 0 <= choice_idx < len(candidates):
                return candidates[choice_idx], "用户手动选择"
            else:
                print(f"  无效输入，请输入 1 到 {len(candidates)} 之间的数字。")
        except (ValueError, EOFError):
            print(f"  无效输入，请输入 1 到 {len(candidates)} 之间的数字。")
        except KeyboardInterrupt:
            print("\n  用户取消操作。")
            sys.exit(1)


def parse_duplicate_report(report_path: str) -> list[dict]:
    """
    解析 duplicate_report.csv 文件。
    
    Args:
        report_path: 报告文件路径
    
    Returns:
        重复文件组列表
    """
    duplicates = []
    
    with open(report_path, "r", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        header = next(reader)  # 读取表头
        
        # 解析表头，确定列的含义
        for row in reader:
            if not row or len(row) < 4:
                continue
            
            md5 = row[0]
            sha256 = row[1]
            file_size = int(row[2]) if row[2] else 0
            count = int(row[3]) if row[3] else 0
            
            files = []
            mtimes = []
            
            # 从第5列开始，每两列一组（路径 + 修改时间）
            for i in range(4, len(row), 2):
                if i < len(row) and row[i]:
                    filepath = row[i]
                    mtime_str = row[i + 1] if i + 1 < len(row) else ""
                    
                    # 将时间字符串转回时间戳
                    try:
                        if mtime_str:
                            dt = datetime.strptime(mtime_str, "%Y-%m-%d %H:%M:%S")
                            mtime = dt.timestamp()
                        else:
                            mtime = os.path.getmtime(filepath) if os.path.exists(filepath) else 0.0
                    except (ValueError, OSError):
                        mtime = os.path.getmtime(filepath) if os.path.exists(filepath) else 0.0
                    
                    files.append(filepath)
                    mtimes.append(mtime)
            
            if files:
                duplicates.append({
                    "md5": md5,
                    "sha256": sha256,
                    "size": file_size,
                    "count": count,
                    "files": files,
                    "mtimes": mtimes,
                })
    
    return duplicates


def delete_file(filepath: str, mode: str = "recycle") -> bool:
    """
    删除文件。
    
    Args:
        filepath: 文件路径
        mode: 删除模式 - "delete"(永久删除), "recycle"(回收站), "dry-run"(模拟)
    
    Returns:
        True 如果删除成功或模拟模式
    """
    if not os.path.exists(filepath):
        print(f"    [跳过] 文件不存在: {filepath}")
        return False
    
    if mode == "dry-run":
        print(f"    [模拟] 将删除: {filepath}")
        return True
    
    if mode == "recycle":
        if HAS_SEND2TRASH:
            try:
                send2trash.send2trash(filepath)
                print(f"    [回收站] 已移至回收站: {filepath}")
                return True
            except (OSError, PermissionError, FileNotFoundError) as e:
                print(f"    [错误] 无法移至回收站: {filepath}")
                print(f"           原因: {e}")
                response = input("    是否改为永久删除？(y/N): ").strip().lower()
                if response != "y":
                    print(f"    [跳过] 用户选择不永久删除: {filepath}")
                    return False
        else:
            print(f"    [错误] send2trash 未安装，无法使用回收站模式")
            return False

    # 永久删除
    try:
        os.remove(filepath)
        print(f"    [已删除] {filepath}")
        return True
    except OSError as e:
        print(f"    [错误] 删除失败: {filepath} ({e})")
        return False


def process_duplicates(
    duplicates: list[dict],
    root_dir: str,
    mode: str = "recycle",
    auto_confirm: bool = False,
) -> dict:
    """
    处理所有重复文件组。
    
    Args:
        duplicates: 重复文件组列表
        root_dir: 原始扫描根目录
        mode: 删除模式
        auto_confirm: 是否自动确认（跳过确认提示）
    
    Returns:
        处理统计信息
    """
    stats = {
        "groups_processed": 0,
        "files_deleted": 0,
        "files_kept": 0,
        "files_skipped": 0,
        "files_verify_failed": 0,
        "space_freed": 0,
        "errors": 0,
    }
    
    total_groups = len(duplicates)
    total_dup_files = sum(d["count"] for d in duplicates)
    
    print()
    print("=" * 60)
    print("  重复文件删除器 - 开始处理")
    print("=" * 60)
    print(f"  重复文件组: {total_groups} 组")
    print(f"  涉及文件数: {total_dup_files} 个")
    print(f"  预计可释放: {format_size(sum(d['size'] * (d['count'] - 1) for d in duplicates))}")
    print(f"  删除模式:   {mode}")
    print(f"  根目录:     {root_dir}")
    print()
    
    # 显示概览
    if not auto_confirm:
        print("-" * 60)
        print("  即将处理以下重复文件组：")
        print("-" * 60)
        for i, dup in enumerate(duplicates, 1):
            print(f"\n  组 {i}/{total_groups}:")
            print(f"    MD5:    {dup['md5']}")
            print(f"    SHA256: {dup['sha256']}")
            print(f"    大小:   {format_size(dup['size'])}")
            print(f"    数量:   {dup['count']} 份")
            for j, f in enumerate(dup["files"], 1):
                exists = "✓" if os.path.exists(f) else "✗"
                mtime_str = datetime.fromtimestamp(dup["mtimes"][j-1]).strftime("%Y-%m-%d %H:%M:%S")
                print(f"      {j}. [{exists}] {f} ({mtime_str})")
        
        print()
        confirm = input("  确认开始处理？(y/N): ").strip().lower()
        if confirm != "y":
            print("  操作已取消。")
            return stats
    
    # 逐组处理
    for i, dup in enumerate(duplicates, 1):
        print()
        print("=" * 60)
        print(f"  处理组 {i}/{total_groups}")
        print(f"  MD5:    {dup['md5']}")
        print(f"  SHA256: {dup['sha256']}")
        print(f"  大小:   {format_size(dup['size'])}")
        print("=" * 60)
        
        files = dup["files"]
        mtimes = dup["mtimes"]
        
        # 过滤掉不存在的文件
        existing_indices = []
        for j, filepath in enumerate(files):
            if os.path.exists(filepath):
                existing_indices.append(j)
            else:
                print(f"    [跳过] 文件不存在: {filepath}")
                stats["files_skipped"] += 1
        
        if len(existing_indices) <= 1:
            print("  只剩 0 或 1 个文件，无需处理。")
            stats["groups_processed"] += 1
            continue
        
        existing_files = [files[j] for j in existing_indices]
        existing_mtimes = [mtimes[j] for j in existing_indices]

        # 验证所有文件的哈希是否与报告一致
        print("  验证文件哈希与报告一致性...")
        hash_verified_files = []
        hash_verified_mtimes = []
        for j, filepath in enumerate(existing_files):
            if verify_file_hash(filepath, dup["md5"], dup["sha256"]):
                hash_verified_files.append(filepath)
                hash_verified_mtimes.append(existing_mtimes[j])
            else:
                print(f"    ⚠ 哈希不一致，跳过: {filepath}")
                print(f"    （文件在扫描后被修改，或报告数据不准确）")
                stats["files_verify_failed"] += 1

        if len(hash_verified_files) <= 1:
            print("  哈希验证后只剩 0 或 1 个文件，无需处理。")
            stats["groups_processed"] += 1
            continue

        existing_files = hash_verified_files
        existing_mtimes = hash_verified_mtimes

        # 选择要保留的文件
        keep_idx, reason = select_file_to_keep(existing_files, existing_mtimes, root_dir, dup["md5"], dup["sha256"])
        keep_file = existing_files[keep_idx]
        
        print(f"\n  ► 保留: {keep_file}")
        print(f"    原因: {reason}")
        stats["files_kept"] += 1
        
        # 对要删除的文件逐个验证并删除
        for j, filepath in enumerate(existing_files):
            if j == keep_idx:
                continue
            
            # 验证：逐字节比对
            print(f"\n  验证文件一致性:")
            print(f"    保留: {keep_file}")
            print(f"    比对: {filepath}")
            
            if not os.path.exists(filepath):
                print(f"    [跳过] 文件已不存在: {filepath}")
                stats["files_skipped"] += 1
                continue
            
            if not os.path.exists(keep_file):
                print(f"    [错误] 保留文件不存在: {keep_file}")
                stats["errors"] += 1
                continue
            
            is_identical = verify_files_identical(keep_file, filepath)
            
            if not is_identical:
                print(f"    ⚠ 字节不一致！跳过删除: {filepath}")
                print(f"    （哈希相同但实际内容不同，可能存在哈希碰撞或文件被修改）")
                stats["files_verify_failed"] += 1
                continue
            
            print(f"    ✓ 字节完全一致，确认可删除")
            
            # 执行删除
            if delete_file(filepath, mode):
                stats["files_deleted"] += 1
                stats["space_freed"] += dup["size"]
            else:
                stats["errors"] += 1
        
        stats["groups_processed"] += 1
    
    return stats


def main():
    parser = argparse.ArgumentParser(
        description="重复文件删除器 - 删除重复文件，仅保留一份副本",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python file_duplicate_deleter.py duplicate_report.csv --root /path/to/folder
  python file_duplicate_deleter.py duplicate_report.csv --mode dry-run
  python file_duplicate_deleter.py duplicate_report.csv --mode recycle
  python file_duplicate_deleter.py duplicate_report.csv --mode delete
  python file_duplicate_deleter.py duplicate_report.csv --yes

保留策略:
  1. 保留文件修改时间最新的
  2. 若文件修改时间相同，保留所在文件夹修改时间最新的
  3. 若文件夹时间也相同，向上追溯父级目录修改时间
  4. 若所有策略均无法区分，让用户手动选择

安全措施:
  - 删除前逐字节验证文件完全一致
  - 支持 dry-run 模式预览
  - 支持回收站模式（需安装 send2trash: pip install send2trash）
        """,
    )
    parser.add_argument(
        "report",
        help="duplicate_report.csv 文件路径（由 file_hash_analyzer.py 生成）",
    )
    parser.add_argument(
        "--root", "-r",
        help="原始扫描的根目录路径（用于追溯文件夹日期时的边界，默认从报告文件路径推断）",
        default=None,
    )
    parser.add_argument(
        "--mode", "-m",
        choices=["delete", "recycle", "dry-run"],
        default="recycle",
        help="删除模式: recycle=回收站(默认), delete=永久删除, dry-run=模拟",
    )
    parser.add_argument(
        "--yes", "-y",
        action="store_true",
        help="跳过确认提示，直接开始处理",
    )
    
    args = parser.parse_args()
    
    # 检查报告文件
    if not os.path.exists(args.report):
        print(f"错误: 报告文件不存在 - {args.report}", file=sys.stderr)
        sys.exit(1)
    
    # 确定根目录
    if args.root:
        root_dir = str(Path(args.root).resolve())
    else:
        # 尝试从同目录的 summary.txt 推断
        report_dir = os.path.dirname(os.path.abspath(args.report))
        summary_path = os.path.join(report_dir, "summary.txt")
        root_dir = report_dir  # 默认使用报告所在目录
        print(f"提示: 未指定 --root，使用报告目录作为根目录: {root_dir}")
        print(f"      如果不正确，请使用 --root 参数指定原始扫描根目录")
    
    if not os.path.isdir(root_dir):
        print(f"错误: 根目录不存在 - {root_dir}", file=sys.stderr)
        sys.exit(1)
    
    # 回收站模式检查
    if args.mode == "recycle" and not HAS_SEND2TRASH:
        print("错误: send2trash 未安装，无法使用回收站模式。")
        print("      安装方法: pip install send2trash")
        print()
        print("请选择替代方案：")
        print("  1. 安装 send2trash 后重新运行（推荐）")
        print("  2. 使用 --mode dry-run 先预览")
        print("  3. 使用 --mode delete 永久删除（需谨慎）")
        print()
        sys.exit(1)
    
    print("=" * 60)
    print("       重复文件删除器 (Duplicate File Deleter)")
    print("=" * 60)
    print()
    
    # 解析报告
    print("正在解析重复文件报告...")
    duplicates = parse_duplicate_report(args.report)
    
    if not duplicates:
        print("报告中没有重复文件，无需处理。")
        sys.exit(0)
    
    print(f"解析完成: {len(duplicates)} 组重复文件")
    
    # 处理重复文件
    stats = process_duplicates(
        duplicates,
        root_dir,
        mode=args.mode,
        auto_confirm=args.yes,
    )
    
    # 输出统计
    print()
    print("=" * 60)
    print("  处理完成！统计信息:")
    print("=" * 60)
    print(f"  处理的文件组:     {stats['groups_processed']}")
    print(f"  保留的文件:       {stats['files_kept']}")
    print(f"  删除的文件:       {stats['files_deleted']}")
    print(f"  跳过的文件:       {stats['files_skipped']}")
    print(f"  验证失败的文件:   {stats['files_verify_failed']}")
    print(f"  出错的文件:       {stats['errors']}")
    print(f"  释放的空间:       {format_size(stats['space_freed'])}")
    
    if stats["files_verify_failed"] > 0:
        print()
        print("  ⚠ 注意: 有文件哈希相同但字节不一致，这可能表示：")
        print("    - 哈希碰撞（极少见）")
        print("    - 文件在扫描后被修改")
        print("    - 文件系统问题")
        print("  这些文件未被删除，请手动检查。")
    
    # 保存处理日志
    log_dir = os.path.dirname(os.path.abspath(args.report))
    log_path = os.path.join(log_dir, "deletion_log.txt")
    
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(f"\n{'=' * 60}\n")
        f.write(f"处理时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"删除模式: {args.mode}\n")
        f.write(f"处理组数: {stats['groups_processed']}\n")
        f.write(f"删除文件: {stats['files_deleted']}\n")
        f.write(f"保留文件: {stats['files_kept']}\n")
        f.write(f"释放空间: {format_size(stats['space_freed'])}\n")
        f.write(f"验证失败: {stats['files_verify_failed']}\n")
        f.write(f"错误:     {stats['errors']}\n")
    
    print(f"\n  处理日志已追加至: {log_path}")


if __name__ == "__main__":
    main()
