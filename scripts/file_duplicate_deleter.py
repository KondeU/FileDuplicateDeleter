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
  4. 若一直追溯到扫描根目录仍无法区分，则让用户手动选择

安全措施：
  - 删除前对每个疑似重复文件进行逐字节二进制比对，确保真正完全一致
  - 仅当字节完全一致时才执行删除
  - 删除操作使用"移动到回收站"模式（如支持）或永久删除（需确认）

依赖文件（需在同一目录）：
  - duplicate_report.csv  - 重复文件报告
  - root_path.csv         - 扫描根目录路径

用法:
  python file_duplicate_deleter.py <duplicate_report.csv> [--mode <recycle|delete|dry-run>]

参数说明:
  duplicate_report.csv  - 由 file_hash_analyzer.py 生成的重复报告文件
  --mode                - 删除模式:
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


def get_ancestral_mtime_from_root(filepath: str, root_dir: str) -> list[tuple[str, float]]:
    """
    从 root_dir 开始向下，获取到文件所在目录的所有祖先目录修改时间。
    
    从 root_dir 开始，依次向下直到文件所在目录。
    这样可以保证不同深度的文件在比较时"对齐"到同一层级。
    
    Args:
        filepath: 文件路径
        root_dir: 根目录路径（起点）
    
    Returns:
        [(目录路径, 修改时间), ...] 列表，从 root_dir 到文件所在目录
    """
    root_path = Path(root_dir).resolve()
    file_path = Path(filepath).resolve()
    
    # 获取从 root 到文件所在目录的路径列表
    path_chain = []
    current = file_path.parent
    
    # 先收集从文件目录到 root 的路径（向上）
    while True:
        path_chain.append(current)
        if current == root_path or current.parent == current:
            break
        current = current.parent
    
    # 反转：从 root 到文件目录（向下）
    path_chain = path_chain[::-1]
    
    # 获取每个目录的 mtime
    result = []
    for p in path_chain:
        try:
            mtime = os.path.getmtime(str(p))
        except OSError:
            mtime = 0.0
        result.append((str(p), mtime))
    
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
    
    # 获取每个候选文件的祖先目录时间线（从 root 开始向下）
    ancestral_mtimes = {}
    for i in candidates:
        ancestral_mtimes[i] = get_ancestral_mtime_from_root(files[i], root_dir)
    
    # 逐级比较（从 root 开始向下，depth=0 总是 root）
    max_depth = max(len(v) for v in ancestral_mtimes.values())
    
    for depth in range(max_depth):
        # depth 0 总是 root_dir，所有文件都相同，跳过
        if depth == 0:
            continue
        
        # 收集该深度所有候选的目录信息
        level_info = {}
        all_have_this_depth = True
        
        for i in candidates:
            if depth < len(ancestral_mtimes[i]):
                dir_path, dir_mtime = ancestral_mtimes[i][depth]
                level_info[i] = (dir_path, dir_mtime)
            else:
                # 该文件的祖先链已结束（层级较浅）
                all_have_this_depth = False
        
        # 如果有的文件祖先链较短，说明文件在不同层级的目录
        # 无法公平比较同一层级，进入策略4
        if not all_have_this_depth:
            break
        
        # 检查是否所有候选在该层级都指向同一个目录
        unique_dirs = set(info[0] for info in level_info.values())
        if len(unique_dirs) == 1:
            # 都在同一目录，无法区分，继续下一层级
            continue
        
        # 不同目录，比较修改时间
        max_mtime = max(info[1] for info in level_info.values())
        new_candidates = [i for i, info in level_info.items() if info[1] == max_mtime]
        
        if len(new_candidates) == 1:
            # 找到唯一候选
            dir_path = level_info[new_candidates[0]][0]
            mtime_str = datetime.fromtimestamp(max_mtime).strftime("%Y-%m-%d %H:%M:%S")
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


def read_root_path(root_path_file: str) -> str:
    """
    从 root_path.csv 文件读取扫描根目录。
    
    Args:
        root_path_file: root_path.csv 文件路径
    
    Returns:
        扫描根目录路径
    
    Raises:
        ValueError: 如果文件格式不正确
    """
    with open(root_path_file, "r", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        header = next(reader)  # 读取表头
        row = next(reader)     # 读取数据行
        if not row or len(row) < 1:
            raise ValueError(f"root_path.csv 文件格式不正确: {root_path_file}")
        return row[0]


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
    log_file: Optional[object] = None,
) -> dict:
    """
    处理所有重复文件组。
    
    Args:
        duplicates: 重复文件组列表
        root_dir: 原始扫描根目录
        mode: 删除模式
        auto_confirm: 是否自动确认（跳过确认提示）
        log_file: 日志文件对象（已打开），用于记录详细处理信息
    
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
        "cancelled": False,
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
            stats["cancelled"] = True
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
        
        # 写入日志文件
        if log_file:
            log_file.write(f"\n{'─' * 60}\n")
            log_file.write(f"组 {i}/{total_groups}\n")
            log_file.write(f"MD5:    {dup['md5']}\n")
            log_file.write(f"SHA256: {dup['sha256']}\n")
            log_file.write(f"大小:   {format_size(dup['size'])}\n")
            log_file.write(f"原始文件数: {dup['count']}\n")
        
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
            if log_file:
                log_file.write(f"\n[结果] 文件不存在或只剩1个，跳过处理\n")
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
            if log_file:
                log_file.write(f"\n[结果] 哈希验证后只剩0或1个文件，跳过处理\n")
            continue

        existing_files = hash_verified_files
        existing_mtimes = hash_verified_mtimes

        # 选择要保留的文件
        keep_idx, reason = select_file_to_keep(existing_files, existing_mtimes, root_dir, dup["md5"], dup["sha256"])
        keep_file = existing_files[keep_idx]
        
        print(f"\n  ► 保留: {keep_file}")
        print(f"    原因: {reason}")
        stats["files_kept"] += 1
        
        # 写入日志文件 - 保留的文件
        if log_file:
            log_file.write(f"\n[保留文件]\n")
            log_file.write(f"  文件: {keep_file}\n")
            log_file.write(f"  原因: {reason}\n")
            log_file.write(f"\n[待删除文件]\n")
        
        deleted_files = []
        skipped_files = []
        
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
                skipped_files.append((filepath, "文件已不存在"))
                continue
            
            if not os.path.exists(keep_file):
                print(f"    [错误] 保留文件不存在: {keep_file}")
                stats["errors"] += 1
                skipped_files.append((filepath, "保留文件不存在"))
                continue
            
            is_identical = verify_files_identical(keep_file, filepath)
            
            if not is_identical:
                print(f"    ⚠ 字节不一致！跳过删除: {filepath}")
                print(f"    （哈希相同但实际内容不同，可能存在哈希碰撞或文件被修改）")
                stats["files_verify_failed"] += 1
                skipped_files.append((filepath, "字节不一致"))
                continue
            
            print(f"    ✓ 字节完全一致，确认可删除")
            
            # 执行删除
            if delete_file(filepath, mode):
                stats["files_deleted"] += 1
                stats["space_freed"] += dup["size"]
                deleted_files.append(filepath)
            else:
                stats["errors"] += 1
                skipped_files.append((filepath, "删除失败"))
        
        # 写入日志文件 - 删除结果
        if log_file:
            if deleted_files:
                log_file.write(f"  已删除 ({len(deleted_files)} 个):\n")
                for f in deleted_files:
                    log_file.write(f"    - {f}\n")
            if skipped_files:
                log_file.write(f"  未删除 ({len(skipped_files)} 个):\n")
                for f, reason in skipped_files:
                    log_file.write(f"    - {f} ({reason})\n")
            log_file.write(f"\n本组统计: 保留 1 个, 删除 {len(deleted_files)} 个, 未删除 {len(skipped_files)} 个\n")
        
        stats["groups_processed"] += 1
    
    return stats


def main():
    parser = argparse.ArgumentParser(
        description="重复文件删除器 - 删除重复文件，仅保留一份副本",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python file_duplicate_deleter.py duplicate_report.csv
  python file_duplicate_deleter.py duplicate_report.csv --mode dry-run
  python file_duplicate_deleter.py duplicate_report.csv --mode recycle
  python file_duplicate_deleter.py duplicate_report.csv --mode delete
  python file_duplicate_deleter.py duplicate_report.csv --yes

依赖文件（需在同一目录）:
  - duplicate_report.csv  - 重复文件报告
  - root_path.csv         - 扫描根目录路径

保留策略:
  1. 保留文件修改时间最新的
  2. 若文件修改时间相同，保留所在文件夹修改时间最新的
  3. 若文件夹时间也相同，向上追溯父级目录修改时间
  4. 若所有策略均无法区分，让用户手动选择

安全措施:
  - 删除前逐字节验证文件完全一致
  - 支持 dry-run 模式预览
  - 支持回收站模式（
        需安装 send2trash: pip install send2trash
        windows 环境可如下安装 send2trash: python -m pip install send2trash
    ）
        """,
    )
    parser.add_argument(
        "report",
        help="duplicate_report.csv 文件路径（由 file_hash_analyzer.py 生成）",
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
    
    # 确定报告目录
    report_dir = os.path.dirname(os.path.abspath(args.report))
    root_path_file = os.path.join(report_dir, "root_path.csv")
    
    # 前置依赖文件检查
    missing_files = []
    if not os.path.exists(args.report):
        missing_files.append(args.report)
    if not os.path.exists(root_path_file):
        missing_files.append(root_path_file)
    
    if missing_files:
        print("错误: 缺少必要的依赖文件:", file=sys.stderr)
        for f in missing_files:
            print(f"       - {f}", file=sys.stderr)
        print()
        print("请确保以下文件在同一目录:", file=sys.stderr)
        print("  - duplicate_report.csv  （由 file_hash_analyzer.py 生成）", file=sys.stderr)
        print("  - root_path.csv         （由 file_hash_analyzer.py 生成）", file=sys.stderr)
        print()
        print("请先运行 file_hash_analyzer.py 生成这些文件:", file=sys.stderr)
        print("  python file_hash_analyzer.py <要扫描的文件夹>", file=sys.stderr)
        sys.exit(1)
    
    # 从 root_path.csv 读取扫描根目录
    try:
        root_dir = read_root_path(root_path_file)
    except ValueError as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)
    
    if not os.path.isdir(root_dir):
        print(f"错误: 扫描根目录不存在 - {root_dir}", file=sys.stderr)
        print("       可能该目录已被删除或移动", file=sys.stderr)
        sys.exit(1)
    
    # 回收站模式检查
    if args.mode == "recycle" and not HAS_SEND2TRASH:
        print("错误: send2trash 未安装，无法使用回收站模式。")
        print("      安装方法: pip install send2trash")
        print("      Windows 下单独安装 Python 时 pip 在 python/scripts 下，")
        print("      如上述指令失败可尝试使用: python -m pip install send2trash")
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
    
    # 打开日志文件
    log_dir = os.path.dirname(os.path.abspath(args.report))
    log_path = os.path.join(log_dir, "deletion_log.txt")
    
    with open(log_path, "a", encoding="utf-8") as log_file:
        # 写入日志头部
        log_file.write(f"\n{'=' * 60}\n")
        log_file.write(f"处理时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        log_file.write(f"扫描根目录: {root_dir}\n")
        log_file.write(f"删除模式: {args.mode}\n")
        log_file.write(f"重复文件组数: {len(duplicates)}\n")
        log_file.write(f"{'=' * 60}\n")
        
        # 处理重复文件
        stats = process_duplicates(
            duplicates,
            root_dir,
            mode=args.mode,
            auto_confirm=args.yes,
            log_file=log_file,
        )
        
        # 写入日志尾部 - 统计信息
        if stats["cancelled"]:
            log_file.write(f"\n{'=' * 60}\n")
            log_file.write(f"[用户取消操作]\n")
            log_file.write(f"{'=' * 60}\n")
            log_file.write(f"未进行任何删除操作。\n")
        else:
            log_file.write(f"\n{'=' * 60}\n")
            log_file.write(f"处理结果统计:\n")
            log_file.write(f"{'=' * 60}\n")
            log_file.write(f"  处理的文件组:     {stats['groups_processed']}\n")
            log_file.write(f"  保留的文件:       {stats['files_kept']}\n")
            log_file.write(f"  删除的文件:       {stats['files_deleted']}\n")
            log_file.write(f"  跳过的文件:       {stats['files_skipped']}\n")
            log_file.write(f"  验证失败的文件:   {stats['files_verify_failed']}\n")
            log_file.write(f"  出错的文件:       {stats['errors']}\n")
            log_file.write(f"  释放的空间:       {format_size(stats['space_freed'])}\n")
            
            if stats["files_verify_failed"] > 0:
                log_file.write(f"\n注意: 有 {stats['files_verify_failed']} 个文件哈希相同但字节不一致，已跳过删除。\n")
    
    # 输出统计
    print()
    if stats["cancelled"]:
        print("=" * 60)
        print("  操作已取消")
        print("=" * 60)
        print("  未进行任何删除操作。")
    else:
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
    
    print(f"\n  处理日志已保存至: {log_path}")


if __name__ == "__main__":
    main()
