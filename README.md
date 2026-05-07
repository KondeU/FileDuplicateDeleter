# FileDuplicateDeleter

安全的重复文件识别与删除工具，帮助你清理磁盘中的重复文件，释放存储空间。

---

## 功能特性

- 🔍 **智能识别**: 通过 MD5 + SHA256 双重哈希精确识别重复文件
- 🗑️ **安全删除**: 删除前逐字节验证，确保真正一致才删除
- ♻️ **回收站模式**: 默认移至回收站，可随时恢复
- 📊 **详细报告**: 完整的扫描报告和处理日志
- 🎯 **智能保留**: 多层策略自动选择最该保留的文件
- 👤 **用户控制**: 无法自动决定时让用户手动选择

---

## 快速开始

### 1. 安装依赖

```bash
# 基础使用（仅扫描）
无需额外依赖

# 安全删除（推荐）
pip install send2trash

# Windows 用户如果 pip 命令失败，可使用：
python -m pip install send2trash
```

### 2. 扫描文件夹

```bash
python scripts/file_hash_analyzer.py "D:\你的文件夹路径"
```

扫描完成后，在 `output/` 目录生成：
- `duplicate_report.csv` - 重复文件报告
- `root_path.csv` - 扫描根目录
- `file_hashes.csv` - 完整哈希表
- `summary.txt` - 分析摘要

### 3. 预览删除计划（重要！）

```bash
python scripts/file_duplicate_deleter.py output/duplicate_report.csv --mode dry-run
```

**强烈建议先预览**，确认无误后再执行删除。

### 4. 执行删除

```bash
# 默认模式：移至回收站（推荐）
python scripts/file_duplicate_deleter.py output/duplicate_report.csv

# 查看处理结果
type output\deletion_log.txt
```

---

## 工作流程

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│   扫描阶段      │  →   │   分析阶段      │  →   │   删除阶段      │
│  analyzer.py    │      │   报告生成      │      │  deleter.py     │
└─────────────────┘      └─────────────────┘      └─────────────────┘

扫描：                     分析：                    删除：
  遍历所有文件              按(MD5+SHA256)分组        选择保留文件
  计算双重哈希              筛选重复组                三层验证
  记录文件信息              生成报告                  执行删除
```

---

## 保留策略详解

当发现一组重复文件时，工具会智能选择保留哪一个：

### 策略优先级

| 优先级 | 策略 | 说明 | 示例 |
|--------|------|------|------|
| 1 | **文件修改时间** | 保留最新的 | `2024-01-15` > `2023-06-01` |
| 2 | **所在目录修改时间** | 文件时间相同时，比较目录 | `最新文件夹` > `旧文件夹` |
| 3 | **向上追溯父目录** | 目录时间相同，向上追溯 | 逐级比较父目录时间 |
| 4 | **用户手动选择** | 无法自动区分时 | 显示所有候选让你选择 |

### 目录追溯机制

```
示例: D:\Photos\A\B\photo.jpg vs D:\Photos\C\D\photo.jpg
                  ↑                       ↑
              文件相同时间              文件相同时间

追溯过程:
  depth 1: 比较 A vs C 的修改时间
  depth 2: 比较 A\B vs C\D 的修改时间
  → 选择目录时间最新的那个分支
```

### 深度差异保护

如果两个文件在不同层级（如 `A\a.jpg` vs `A\B\a.jpg`），工具会进入用户选择模式，而非自动判断。这是**保守安全策略**，避免误删用户可能想保留的文件。

---

## 安全机制

### 三层验证确保安全

| 验证层 | 检查内容 | 目的 |
|--------|----------|------|
| 第1层 | 文件存在性 | 跳过已删除的文件 |
| 第2层 | 哈希一致性 | 检测扫描后被修改的文件 |
| 第3层 | 逐字节比对 | 最终确认内容完全相同 |

只有三层全部通过，才会执行删除。

### 删除模式对比

| 模式 | 说明 | 安全性 | 使用场景 |
|------|------|--------|----------|
| `dry-run` | 仅模拟，不实际删除 | 最高 | **首次必用** |
| `recycle` | 移至回收站（默认） | 高 | 日常使用 |
| `delete` | 永久删除 | 中 | 确认无误后 |

### 文件修改保护

如果在扫描后文件被修改了：

```
扫描时: photo.jpg 内容 = "ABC"  → 哈希 = abc123
删除前: photo.jpg 内容 = "XYZ"  → 哈希 = xyz789

哈希不一致 → 跳过删除 → 保护用户数据
```

---

## 使用示例

### 场景1: 清理照片文件夹

```bash
# 扫描照片目录
python scripts/file_hash_analyzer.py "D:\Photos"

# 查看摘要
type output\summary.txt

# 预览删除计划
python scripts/file_duplicate_deleter.py output/duplicate_report.csv --mode dry-run

# 执行删除（回收站模式）
python scripts/file_duplicate_deleter.py output/duplicate_report.csv
```

### 场景2: 自动化处理（跳过确认）

```bash
# 扫描并自动确认
python scripts/file_duplicate_deleter.py output/duplicate_report.csv --yes

# 注意：--yes 会跳过确认提示，请确保先用 dry-run 预览
```

### 场景3: 仅扫描不删除

```bash
# 只想看有哪些重复文件
python scripts/file_hash_analyzer.py "D:\Downloads"
type output\summary.txt
# 不执行 deleter，保留报告作为参考
```

---

## 输出文件说明

### duplicate_report.csv

重复文件报告，每组一行：

| 列 | 内容 |
|----|------|
| MD5哈希 | 文件的MD5值 |
| SHA256哈希 | 文件的SHA256值 |
| 文件大小 | 字节数 |
| 重复数量 | 有多少个副本 |
| 文件路径_1 | 第1个重复文件 |
| 修改时间_1 | 第1个文件的修改时间 |
| 文件路径_2 | 第2个重复文件 |
| ... | 更多重复文件 |

### deletion_log.txt

删除处理日志：

```
============================================================
处理时间: 2024-01-15 10:30:00
扫描根目录: D:\Photos
删除模式: recycle
============================================================

────────────────────────────────────
组 1/5
MD5:    abc123...
SHA256: def456...
大小:   1.50 MB

[保留文件]
  文件: D:\Photos\2024\photo.jpg
  原因: 文件修改时间最新

[待删除文件]
  已删除 (2 个):
    - D:\Photos\backup\photo.jpg
    - D:\Photos\old\photo.jpg
  未删除 (0 个):
```

---

## 注意事项

### ⚠️ 重要提醒

1. **先预览再删除**: 必须先用 `--mode dry-run` 预览
2. **安装 send2trash**: 否则只能永久删除
3. **扫描后尽快处理**: 避免文件在扫描后被修改
4. **保留报告文件**: 可追溯删除历史

### 📋 最佳实践

- 首次使用在小范围测试
- 定期备份重要数据
- 删除前关闭其他程序（避免文件被修改）
- 处理后检查回收站确认结果

### 🔧 常见问题

**Q: 为什么有些文件没有删除？**

A: 可能原因：
- 哈希验证失败（文件被修改）
- 逐字节比对不一致（罕见的哈希碰撞）
- 文件不存在或无权限
- 用户取消操作

查看 `deletion_log.txt` 中的"未删除"列表了解原因。

**Q: 为什么让我手动选择？**

A: 当策略1-3都无法区分时，说明：
- 文件和所有目录的修改时间都相同
- 或文件在不同层级无法公平比较

这是保守策略，确保不误删。

**Q: send2trash 安装失败？**

A: Windows 用户尝试：
```bash
python -m pip install send2trash
```

如果仍失败，使用 `--mode delete` 永久删除（需谨慎）。

---

## 技术原理

### 为什么用 MD5 + SHA256？

双重哈希碰撞概率极低（约 1/2^192），比单一哈希更可靠：

- MD5: 已知有人为构造的碰撞
- SHA256: 目前无已知碰撞
- 两者同时碰撞: 理论上不可行

即使双重哈希相同，删除前仍会逐字节比对确认。

### 逐字节比对

```python
# 64KB 分块读取比对
while True:
    chunk1 = f1.read(65536)
    chunk2 = f2.read(65536)
    if chunk1 != chunk2:
        return False  # 内容不同，跳过
    if not chunk1:
        return True   # 完全相同，可删除
```

这是最终的确认手段，确保真正一致。

### 祖先链追溯

```
root_dir: D:\Photos
文件: D:\Photos\A\B\photo.jpg

祖先链（从root向下）:
  depth 0: D:\Photos      （跳过，都是root）
  depth 1: D:\Photos\A    （比较A的mtime）
  depth 2: D:\Photos\A\B  （比较A\B的mtime）
```

这样设计确保不同深度的文件公平比较。

---

## 项目结构

```
FileDuplicateDeleter/
├── README.md                    # 本文档
├── scripts/
│   ├── file_hash_analyzer.py    # 扫描器
│   ├── file_duplicate_deleter.py # 删除器
│   ├── DELETER_CHAIN_ANALYSIS.md # 详细策略链路分析
│   └── EXECUTION_CHAIN_ANALYSIS.md # 执行链和安全性分析
└── output/                      # 输出目录（自动创建）
    ├── root_path.csv            # 扫描根目录
    ├── duplicate_report.csv     # 重复报告
    ├── file_hashes.csv          # 完整哈希表
    ├── summary.txt              # 分析摘要
    └ deletion_log.txt           # 删除日志
```

---

## 进阶阅读

想深入了解内部机制？

- [DELETER_CHAIN_ANALYSIS.md](scripts/DELETER_CHAIN_ANALYSIS.md) - 详细的策略链路和场景分析
- [EXECUTION_CHAIN_ANALYSIS.md](scripts/EXECUTION_CHAIN_ANALYSIS.md) - 执行链和安全性分析

---

## 许可证

MIT License

---

## 安全承诺

本工具的设计原则：

1. **安全优先** - 宁可跳过，不误删
2. **多层验证** - 三层检查确保一致
3. **用户可控** - 无法决定时让用户选择
4. **可追溯** - 完整日志记录所有操作

你的数据安全是第一位的。