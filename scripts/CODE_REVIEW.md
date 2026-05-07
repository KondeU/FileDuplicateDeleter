# 代码检视报告

**检视日期**: 2026-05-07  
**检视文件**:
- `file_hash_analyzer.py` - 文件哈希分析器
- `file_duplicate_deleter.py` - 重复文件删除器

---

## 一、file_hash_analyzer.py

### 1.1 总体评价

**风险等级**: 🟢 低风险

该脚本仅进行分析操作（扫描、计算哈希、生成报告），不涉及任何文件删除或修改操作，无数据丢失风险。代码实现合理，错误处理完善。

### 1.2 已有的良好实践

- ✅ 正确跳过符号链接（第116-118行），避免重复计算或死循环
- ✅ 对无权限目录进行错误捕获并提示（第100-106行）
- ✅ 使用 MD5 + SHA256 双重哈希，碰撞概率极低
- ✅ 进度显示友好，包含 ETA 估算
- ✅ 输出文件使用 UTF-8-BOM 编码（`utf-8-sig`），Excel 兼容性好

### 1.3 潜在改进建议

| 级别 | 位置 | 描述 | 建议 |
|------|------|------|------|
| 低 | 第51-52行 | 使用 MD5 算法，存在已知碰撞漏洞 | 对于安全性要求极高的场景可考虑移除 MD5，仅使用 SHA256；但当前作为"疑似重复"判定标准已足够 |
| 低 | 第97-106行 | 首先遍历所有文件到内存列表 | 对于超大目录（百万级文件）可能占用较多内存；可考虑流式处理或分批处理 |
| 低 | 无 | 未支持排除特定目录/文件类型 | 可添加 `--exclude` 参数跳过特定目录或文件模式 |

---

## 二、file_duplicate_deleter.py

### 2.1 总体评价

**风险等级**: 🟡 中等风险

该脚本涉及文件删除操作，存在一定的误删风险。虽然已实现多项安全措施，但仍有一些场景可能导致非预期行为。

### 2.2 🔴 高风险问题

#### 问题 1: 回收站失败静默回退永久删除

**位置**: `file_duplicate_deleter.py:336-355`

**问题描述**:
用户选择 `--mode recycle` 模式时，期望文件被移至回收站以便恢复。但当 `send2trash` 调用失败时，脚本会静默回退到永久删除模式，仅打印警告信息。

```python
if mode == "recycle":
    if HAS_SEND2TRASH:
        try:
            send2trash.send2trash(filepath)
            print(f"    [回收站] 已移至回收站: {filepath}")
            return True
        except Exception as e:
            print(f"    [警告] 无法移至回收站，改为永久删除: {filepath} ({e})")
            # 回退到永久删除 - 用户可能不知道发生了什么
```

**风险场景**:
1. 用户误以为文件在回收站可恢复，实际已被永久删除
2. `send2trash` 在某些特殊路径或权限下可能失败
3. 批量处理时，警告信息可能被忽略

**建议修复**:
```python
if mode == "recycle":
    if HAS_SEND2TRASH:
        try:
            send2trash.send2trash(filepath)
            return True
        except Exception as e:
            print(f"    [错误] 无法移至回收站: {filepath}")
            print(f"           原因: {e}")
            # 不自动回退，要求用户确认
            response = input("    是否改为永久删除？(y/N): ").strip().lower()
            if response != "y":
                return False
    else:
        print(f"    [错误] send2trash 未安装，无法使用回收站模式")
        return False
```

---

#### 问题 2: 保留文件未验证哈希一致性

**位置**: `file_duplicate_deleter.py:452-493`

**问题描述**:
脚本选择要保留的文件时，未验证该文件的当前哈希值是否与报告中的哈希一致。如果保留文件在扫描后被修改：

1. 其他待删除文件会与修改后的保留文件进行逐字节比对
2. 比对结果不一致 → 跳过删除（安全）
3. **但保留的可能是被修改后的文件，原始文件反被删除**

**风险场景**:
```
时间线：
1. file_hash_analyzer.py 扫描 A.txt 和 B.txt（内容相同）
2. 用户修改了 A.txt
3. file_duplicate_deleter.py 运行
4. 选择保留 A.txt（因为修改时间最新）
5. A.txt 与 B.txt 比对 → 不一致 → 跳过 B.txt
6. 结果：保留了修改后的 A.txt，但 A.txt 的原始内容已丢失
```

**建议修复**:
在处理每组重复文件前，验证所有文件（包括保留文件）的当前哈希值与报告一致：

```python
# 在 process_duplicates 函数中添加验证步骤
def verify_file_hash(filepath: str, expected_md5: str, expected_sha256: str) -> bool:
    """验证文件哈希是否与预期一致"""
    result = compute_file_hashes(filepath)  # 复用 file_hash_analyzer.py 中的函数
    if result is None:
        return False
    md5, sha256 = result
    return md5 == expected_md5 and sha256 == expected_sha256
```

---

### 2.3 🟡 中等风险问题

#### 问题 3: 报告文件可被篡改

**位置**: `file_duplicate_deleter.py:256-314` (`parse_duplicate_report`)

**问题描述**:
脚本直接信任 CSV 报告内容，未验证文件实际哈希是否与报告一致。恶意构造的报告可能导致误删非重复文件。

**风险场景**:
1. 报告文件被意外或恶意修改
2. 路径被篡改指向不同文件
3. 哈希值被篡改

**建议修复**:
- 添加 `--verify-all` 参数，在处理前重新计算所有文件哈希
- 或在默认模式下随机抽样验证

---

#### 问题 4: --yes 参数绕过确认

**位置**: `file_duplicate_deleter.py:541-544`, `362`, `401`

**问题描述**:
`--yes` / `-y` 参数允许跳过所有确认提示直接执行删除。虽然方便自动化，但也增加了误删风险。

**建议改进**:
- 添加更明显的警告横幅
- 要求用户输入特定确认词（如 "DELETE"）而非简单 `-y`

---

### 2.4 🟢 已有的良好安全措施

| 措施 | 位置 | 说明 |
|------|------|------|
| ✅ 删除前逐字节验证 | `verify_files_identical()` 第57-89行 | 确保文件内容完全一致才删除 |
| ✅ dry-run 模式 | `delete_file()` 第332-334行 | 支持模拟运行，预览删除操作 |
| ✅ 文件不存在自动跳过 | 第328-330行, 第438-442行 | 避免处理已删除文件 |
| ✅ 验证失败不删除 | 第482-486行 | 字节不一致时跳过 |
| ✅ 处理日志记录 | 第619-634行 | 所有操作记录到日志文件 |
| ✅ 多层级保留策略 | `select_file_to_keep()` 第142-253行 | 智能、透明的文件保留决策 |

---

### 2.5 🔵 低风险问题 / 代码质量

#### 问题 5: 文档与实现不符

**位置**: `get_dir_mtime()` 函数，第92-108行

**描述**:
函数文档注释说"如果目录本身的时间戳不足以区分，递归向上查找父级目录"，但实际实现中并未递归。递归查找实际在 `get_ancestral_mtime()` 函数中实现。

```python
def get_dir_mtime(dirpath: str, root_dir: str) -> float:
    """
    获取目录的修改时间。
    如果目录本身的时间戳不足以区分，递归向上查找父级目录。  # ← 文档描述不准确
    ...
    """
    try:
        return os.path.getmtime(dirpath)  # ← 实际只返回目录自身的时间戳
    except OSError:
        return 0.0
```

**建议**:
修正函数文档，或移除此函数（目前未被调用）。

---

#### 问题 6: 异常处理过于宽泛

**位置**: 第342行, 第88行

**描述**:
使用 `except Exception` 和 `except OSError` 捕获所有异常，可能掩盖特定错误。

```python
except Exception as e:  # 过于宽泛
```

**建议**:
捕获具体异常类型，如 `PermissionError`, `FileNotFoundError` 等。

---

#### 问题 7: 第231行占位符未使用

**位置**: 第231行

```python
print(f"  MD5: {root_dir}")  # placeholder, will be overridden
```

这行代码打印的是 `root_dir` 而非实际 MD5，注释说明是占位符但实际未被覆盖。应在函数参数中传入 MD5 值。

---

### 2.6 功能建议

| 建议 | 优先级 | 描述 |
|------|--------|------|
| 添加 `--backup-dir` 参数 | 中 | 删除前将文件备份到指定目录 |
| 支持 `--undo` 回滚 | 中 | 从日志文件恢复上次的删除操作（仅回收站模式） |
| 添加 `--verify` 参数 | 高 | 处理前验证所有文件哈希与报告一致 |
| 支持正则排除 | 低 | `--exclude-pattern` 排除特定文件 |
| 添加交互式逐个确认 | 低 | 每组重复文件手动确认删除哪些 |

---

## 三、总结

### 风险矩阵

| 文件 | 风险等级 | 主要风险 |
|------|----------|----------|
| `file_hash_analyzer.py` | 🟢 低 | 无删除操作，仅分析 |
| `file_duplicate_deleter.py` | 🟡 中等 | 回收站回退、保留文件未验证 |

### 建议优先修复项

1. **[高优先级]** 回收站失败时不应静默回退永久删除
2. **[高优先级]** 处理前验证所有文件哈希一致性
3. **[中优先级]** 添加 `--verify` 参数强制验证模式

### 使用建议

1. **始终先使用 `--mode dry-run` 预览**，确认无问题后再执行
2. **推荐使用 `--mode recycle`**，但确保已安装 `send2trash`
3. **扫描后尽快删除**，避免文件在扫描与删除之间被修改
4. **保留报告文件**，`deletion_log.txt` 记录了所有操作