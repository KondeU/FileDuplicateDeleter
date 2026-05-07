# 执行链分析报告

**分析日期**: 2026-05-07  
**分析文件**:
- `file_hash_analyzer.py` - 文件哈希分析器
- `file_duplicate_deleter.py` - 重复文件删除器

---

## 一、完整工作流程

```
file_hash_analyzer.py                    file_duplicate_deleter.py
        ↓                                          ↓
┌─────────────────────┐                  ┌─────────────────────────┐
│ 1. 扫描文件夹       │                  │ 1. 解析 CSV 报告        │
│ 2. 计算 MD5+SHA256  │                  │ 2. 过滤不存在文件        │
│ 3. 哈希分组         │  ──报告──→       │ 3. 验证文件哈希 ✓       │
│ 4. 输出报告         │                  │ 4. 选择保留文件          │
└─────────────────────┘                  │ 5. 逐字节比对 ✓         │
                                         │ 6. 执行删除             │
                                         └─────────────────────────┘
```

---

## 二、安全验证链分析

| 阶段 | 验证点 | 实现 | 效果 |
|------|--------|------|------|
| **解析** | 文件存在性 | `os.path.exists()` | 跳过已删除文件 |
| **预处理** | 哈希一致性 | `verify_file_hash()` ✓ | 检测扫描后被修改的文件 |
| **选择** | 保留文件存在 | `os.path.exists()` | 避免保留文件丢失 |
| **删除前** | 逐字节比对 | `verify_files_identical()` ✓ | 最终确认内容一致 |

---

## 三、关键场景测试

### 场景1：文件扫描后被修改

```
时间线：
1. 扫描: A.txt(内容X), B.txt(内容X) → 哈希相同，写入报告
2. 用户修改: A.txt → 内容Y
3. 运行删除器:
   - 验证 A.txt 哈希 ≠ 报告哈希 → 跳过 A.txt
   - 验证 B.txt 哈希 = 报告哈希 → 保留 B.txt
   - 只剩1个文件 → 不删除任何文件
```

**结果：✅ 安全，不会误删**

### 场景2：删除过程中文件被其他进程修改

```
1. 哈希验证通过（文件内容与报告一致）
2. 选择保留文件 A
3. 准备删除 B：
   - 逐字节比对 A 和 B
   - 如果此时 A 被修改 → 比对失败 → 跳过删除
```

**结果：✅ 安全，逐字节验证会失败**

### 场景3：回收站失败

```
--mode recycle 但 send2trash 失败:
旧版: 静默回退永久删除
新版: 询问用户 "是否改为永久删除？(y/N)"
```

**结果：✅ 已修复，需用户确认**

### 场景4：报告被篡改

```
恶意修改报告中的哈希值或路径：
1. 文件实际哈希 ≠ 报告哈希 → 第一层验证失败 → 跳过
2. 文件实际哈希 = 报告哈希（碰巧） → 进入逐字节比对
3. 要删除的文件与保留文件内容不同 → 比对失败 → 跳过
```

**结果：✅ 双重验证防止误删**

### 场景5：哈希碰撞（理论上）

```
假设两个不同文件碰巧 MD5+SHA256 相同（概率约 1/2^192）：
1. 扫描时归为重复组
2. 删除器进行逐字节比对
3. 比对失败 → 跳过删除
```

**结果：✅ 逐字节验证兜底**

---

## 四、边界情况检查

| 边界情况 | 处理方式 | 代码位置 | 结果 |
|----------|----------|----------|------|
| 空文件 | 视为正常文件，相同哈希可删除 | 哈希计算正常处理 | ✅ |
| 符号链接 | 分析器跳过 | analyzer:116-118 | ✅ |
| 无权限文件 | 捕获异常，跳过 | try-except 处理 | ✅ |
| 超大文件 | 分块读取（8KB/64KB） | 无内存问题 | ✅ |
| 路径含特殊字符 | 路径用 str 处理 | 正常工作 | ✅ |
| 只剩1个文件 | 直接跳过 | deleter:523-526 | ✅ |
| 保留文件被删除 | 检测并报错 | deleter:554-557 | ✅ |

---

## 五、潜在问题（低风险）

### 问题1：逐字节比对时的 Race Condition

```python
# file_duplicate_deleter.py:126-137
with open(file1, "rb") as f1, open(file2, "rb") as f2:
    while True:
        chunk1 = f1.read(chunk_size)  # 读取 file1
        chunk2 = f2.read(chunk_size)  # 读取 file2（此时 file1 可能已被修改）
        if chunk1 != chunk2:
            return False
```

**风险**：读取 f1 和 f2 之间，文件可能被修改  
**后果**：最坏情况是比对失败，不会误删  
**评估**：低风险，不影响安全目标

### 问题2：报告文件无完整性校验

报告 CSV 未签名，可能被篡改，但：
- 第一层哈希验证会检测内容不一致
- 第二层逐字节比对会检测内容不同

**评估**：低风险

---

## 六、代码修改验证

### 修改点1：新增哈希验证函数

```python
# file_duplicate_deleter.py:58-102
def compute_file_hashes(filepath: str, chunk_size: int = 8192) -> Optional[tuple[str, str]]:
    """计算单个文件的 MD5 和 SHA256 哈希值"""
    ...

def verify_file_hash(filepath: str, expected_md5: str, expected_sha256: str) -> bool:
    """验证文件当前的哈希值是否与报告中的预期哈希一致"""
    ...
```

**作用**：在删除前验证文件未被修改

### 修改点2：处理前验证所有文件哈希

```python
# file_duplicate_deleter.py:510-529
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
        stats["files_verify_failed"] += 1
```

**作用**：防止处理扫描后被修改的文件

### 修改点3：回收站失败处理

```python
# file_duplicate_deleter.py:395-401
except (OSError, PermissionError, FileNotFoundError) as e:
    print(f"    [错误] 无法移至回收站: {filepath}")
    print(f"           原因: {e}")
    response = input("    是否改为永久删除？(y/N): ").strip().lower()
    if response != "y":
        print(f"    [跳过] 用户选择不永久删除: {filepath}")
        return False
```

**作用**：不再静默回退，需用户确认

### 修改点4：用户选择时显示哈希值

```python
# file_duplicate_deleter.py:283-284
print(f"  MD5:    {file_md5}")
print(f"  SHA256: {file_sha256}")
```

**作用**：修复原来的占位符错误

---

## 七、结论

### 安全措施清单

| 安全措施 | 状态 | 说明 |
|----------|------|------|
| 多层验证（哈希+逐字节） | ✅ 已实现 | 双重保险 |
| 文件修改检测 | ✅ 已实现 | 扫描后修改会被发现 |
| 回收站失败处理 | ✅ 已修复 | 需用户确认 |
| 用户确认机制 | ✅ 已实现 | 处理前确认 |
| 详尽日志记录 | ✅ 已实现 | deletion_log.txt |
| dry-run 预览模式 | ✅ 已实现 | 安全预览 |
| 文件不存在处理 | ✅ 已实现 | 自动跳过 |

### 最终评估

**两个脚本能有效达成目标：安全地删除重复文件**

### 推荐使用流程

```bash
# 1. 扫描并生成报告
python file_hash_analyzer.py /path/to/folder

# 2. 先预览（安全第一）
python file_duplicate_deleter.py output/duplicate_report.csv --mode dry-run

# 3. 再用回收站模式（推荐）
python file_duplicate_deleter.py output/duplicate_report.csv --mode recycle

# 4. 最后才用永久删除（确认无误后）
python file_duplicate_deleter.py output/duplicate_report.csv --mode delete
```

---

## 八、风险评估矩阵

| 风险类型 | 可能性 | 影响 | 缓解措施 | 剩余风险 |
|----------|--------|------|----------|----------|
| 误删非重复文件 | 极低 | 高 | 多层验证 | 🟢 极低 |
| 删除过程中文件被修改 | 低 | 中 | 逐字节比对 | 🟢 低 |
| 报告被篡改 | 低 | 高 | 哈希验证 | 🟢 低 |
| 哈希碰撞 | 极低 | 高 | 逐字节比对 | 🟢 极低 |
| 程序崩溃中断 | 低 | 低 | 日志记录 | 🟡 中 |
| 用户误操作 | 中 | 高 | 回收站模式 | 🟡 中 |

**建议**：
1. 始终先用 `--mode dry-run` 预览
2. 优先使用 `--mode recycle` 回收站模式
3. 保留报告文件和日志文件以便追溯