#!/usr/bin/env python3
import re
import sys
import os

def patch_file(file_path):
    if not os.path.exists(file_path):
        print(f"❌ 错误: 找不到目标源码文件 {file_path}")
        sys.exit(1)

    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    # 替换 1：将获取系统家目录的逻辑，强行替换为绝对路径
    p1 = r"homeDir,\s*err\s*:=\s*os\.UserHomeDir\(\)[\s\S]*?homeDir,\s*_\s*=\s*os\.Getwd\(\)\n\s*\}"
    r1 = "// 【核心修改】：直接强行硬编码为你路由器的闪存绝对路径，拒绝让其读取系统的家目录\n\thomeDir := \"/flash/rw/disk/mihomo\"\n"
    content, n1 = re.subn(p1, r1, content)

    # 替换 2：移除 .config/mihomo 拼接逻辑
    p2 = r"homeDir\s*=\s*P\.Join\(homeDir,\s*\".config\",\s*Name\)[\s\S]{1,200}?XDG_CONFIG_HOME[\s\S]{1,150}?\n\s*\}\n\s*\}"
    content, n2 = re.subn(p2, "", content)

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"✅ 成功 Patch 路径: {file_path}")
    print(f"   - 替换1 (家目录硬编码) : 命中 {n1} 处")
    print(f"   - 替换2 (清理 .config) : 命中 {n2} 处")

    if n1 == 0 or n2 == 0:
        print("⚠️ 警告: 有替换未命中！可能是官方源码格式发生了变动，请检查。")

if __name__ == "__main__":
    # 接收终端传入的文件路径参数，如果没有传，则报错提示
    if len(sys.argv) < 2:
        print("用法: python3 patch_mihomo_path.py <path_to_path.go>")
        sys.exit(1)
        
    target_file = sys.argv[1]
    patch_file(target_file)
