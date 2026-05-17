# -*- coding: utf-8 -*-
"""
深度分析脚本：解决 targetSdkVersion 解析失败、检测权限调用完整性
用法：python apk_deep_analysis.py <apk_path> [unpack_dir]
依赖：aapt（需在环境变量或同目录）
输出：在 apk 同目录生成 <apk_name>_deep_analysis.txt
"""

import os
import sys
import re
import subprocess
import xml.etree.ElementTree as ET

# 解决 Windows 控制台编码问题
if sys.stdout.encoding != 'utf-8':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

def get_aapt_path():
    """
    查找 aapt 可执行文件（优先同目录，其次环境变量）
    参考：os.path.dirname 仅处理字符串，需要先获取绝对路径[1](@ref)[7](@ref)
    """
    # 获取当前脚本的绝对路径所在目录
    script_path = os.path.abspath(sys.argv)
    script_dir = os.path.dirname(script_path)   # 脚本所在目录
    candidates = [
        os.path.join(script_dir, 'aapt.exe'),   # 与脚本同一目录
        'aapt.exe',                              # 当前工作目录
        'aapt'                                   # 系统 PATH
    ]
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    return 'aapt'   # 兜底，可能触发 FileNotFoundError

def get_sdk_info_via_aapt(apk_path):
    """
    使用 aapt dump badging 获取真实的 minSdkVersion 和 targetSdkVersion
    参考：https://docs.pingcode.com/baike/754494[4](@ref) 和
         https://ask.csdn.net/questions/9073419[6](@ref)
    """
    aapt = get_aapt_path()
    try:
        result = subprocess.run(
            [aapt, 'dump', 'badging', apk_path],
            capture_output=True, text=True, encoding='utf-8'
        )
        if result.returncode != 0:
            return None, None, result.stderr
        output = result.stdout
        # 匹配 targetSdkVersion 和 sdkVersion（minSdkVersion）
        target_match = re.search(r"targetSdkVersion:'(\d+)'", output)
        min_match = re.search(r"sdkVersion:'(\d+)'", output)  # minSdkVersion
        target_sdk = target_match.group(1) if target_match else None
        min_sdk = min_match.group(1) if min_match else None
        return min_sdk, target_sdk, None
    except FileNotFoundError:
        return None, None, "aapt 未找到，请安装或放置 aapt.exe 到工作目录"
    except Exception as e:
        return None, None, str(e)

def parse_manifest_attributes(unpack_dir):
    """从反编译后的 AndroidManifest.xml 解析属性（备份检查）"""
    manifest_path = os.path.join(unpack_dir, 'AndroidManifest.xml')
    if not os.path.exists(manifest_path):
        return {}
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    ns = {'android': 'http://schemas.android.com/apk/res/android'}
    attrs = {}
    # 检查 uses-sdk 标签
    uses_sdk = root.find('uses-sdk')
    if uses_sdk is not None:
        attrs['minSdkVersion'] = uses_sdk.get(ns.get('android') + 'minSdkVersion', '')
        attrs['targetSdkVersion'] = uses_sdk.get(ns.get('android') + 'targetSdkVersion', '')
        attrs['maxSdkVersion'] = uses_sdk.get(ns.get('android') + 'maxSdkVersion', '')
    # 检查 package 和 version
    attrs['package'] = root.get('package', '')
    attrs['versionCode'] = root.get(ns.get('android') + 'versionCode', '')
    attrs['versionName'] = root.get(ns.get('android') + 'versionName', '')
    return attrs

def check_resources_arsc(apk_path):
    """
    通过 aapt dump resources 检查 targetSdkVersion 是否在 resources.arsc 中
    参见：https://ask.csdn.net/questions/9073419[6](@ref)
    """
    aapt = get_aapt_path()
    try:
        result = subprocess.run(
            [aapt, 'dump', 'resources', apk_path],
            capture_output=True, text=True, encoding='utf-8'
        )
        if result.returncode == 0:
            # 搜索 targetSdkVersion 相关字符串
            if re.search(r'targetSdkVersion', result.stdout, re.IGNORECASE):
                return True
        return False
    except:
        return False

def scan_smali_for_permission_usage(unpack_dir, dangerous_perms):
    """
    扫描 smali 代码，检查每个高危权限是否在调用危险 API 前有 checkSelfPermission
    并统计未检查的权限使用点
    返回：dict { permission: { 'checked': int, 'unchecked': [file_paths] }}
    """
    smali_dir = os.path.join(unpack_dir, 'smali')
    if not os.path.exists(smali_dir):
        return {}

    # 预编译危险权限的 Smali 常量引用模式
    perm_patterns = {}
    for perm in dangerous_perms:
        # 将类似 android.permission.READ_CONTACTS 转为 Smali 中的 Lcom/android/... 引用
        # 实际上在 smali 中常以字符串形式出现，我们匹配 "android.permission.XXX"
        perm_patterns[perm] = re.compile(re.escape(perm))

    # 结果存储
    result = {}
    for perm in dangerous_perms:
        result[perm] = {'checked': 0, 'unchecked': []}

    # 遍历所有 smali 文件
    for root_dir, dirs, files in os.walk(smali_dir):
        for file in files:
            if not file.endswith('.smali'):
                continue
            filepath = os.path.join(root_dir, file)
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            # 对于每个权限，检查是否出现在该文件中
            for perm in dangerous_perms:
                if perm_patterns[perm].search(content):
                    # 检查同一个文件中是否有 checkSelfPermission 调用
                    has_check = 'checkSelfPermission' in content
                    if has_check:
                        result[perm]['checked'] += 1
                    else:
                        # 记录文件相对路径（避免过长）
                        rel_path = os.path.relpath(filepath, smali_dir)
                        result[perm]['unchecked'].append(rel_path)

    return result

def generate_deep_report(apk_path, unpack_dir):
    apk_name = os.path.splitext(os.path.basename(apk_path))
    report_lines = []
    report_lines.append(f"===== APK 深度分析报告 =====")
    report_lines.append(f"分析时间: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append(f"APK 文件: {apk_path}")
    report_lines.append("")

    # 1. 获取真实 SDK 版本（优先使用 aapt）
    report_lines.append("--- 1. Android SDK 版本检测 ---")
    min_sdk, target_sdk, error = get_sdk_info_via_aapt(apk_path)
    if error:
        report_lines.append(f"[错误] aapt 执行失败: {error}")
        report_lines.append("尝试从反编译的 AndroidManifest.xml 获取...")
        attrs = parse_manifest_attributes(unpack_dir)
        min_sdk = attrs.get('minSdkVersion')
        target_sdk = attrs.get('targetSdkVersion')
    else:
        report_lines.append(f"minSdkVersion: {min_sdk or '未设置'}")
        report_lines.append(f"targetSdkVersion: {target_sdk or '未设置'}")
        # 检查 resources.arsc 是否存在隐藏定义
        if not target_sdk and check_resources_arsc(apk_path):
            report_lines.append("[警告] targetSdkVersion 可能被编译到 resources.arsc 中，")
            report_lines.append("       仅修改 AndroidManifest.xml 可能无效。")
            report_lines.append("       建议使用 aapt dump resources 查看具体值。")

    report_lines.append("")

    # 2. 高危权限代码使用审计
    dangerous_perms = [
        'android.permission.READ_CONTACTS', 'android.permission.WRITE_CONTACTS',
        'android.permission.ACCESS_FINE_LOCATION', 'android.permission.ACCESS_COARSE_LOCATION',
        'android.permission.CAMERA', 'android.permission.RECORD_AUDIO',
        'android.permission.READ_CALENDAR', 'android.permission.WRITE_CALENDAR',
        'android.permission.READ_EXTERNAL_STORAGE', 'android.permission.WRITE_EXTERNAL_STORAGE',
        'android.permission.READ_PHONE_STATE', 'android.permission.SEND_SMS',
        'android.permission.RECEIVE_SMS', 'android.permission.BODY_SENSORS',
        'android.permission.READ_CALL_LOG', 'android.permission.WRITE_CALL_LOG',
        'android.permission.PROCESS_OUTGOING_CALLS',
    ]
    report_lines.append("--- 2. 高危权限代码使用审计 ---")
    usage = scan_smali_for_permission_usage(unpack_dir, dangerous_perms)
    has_issue = False
    for perm, info in usage.items():
        if info['checked'] > 0:
            report_lines.append(f"  {perm}: 检查到 {info['checked']} 处有 checkSelfPermission 调用")
        if info['unchecked']:
            has_issue = True
            report_lines.append(f"  {perm}: 发现 {len(info['unchecked'])} 处引用但无 checkSelfPermission!")
            # 仅显示前 5 个文件避免报告过长
            for f in info['unchecked'][:5]:
                report_lines.append(f"      -> {f}")
    if not has_issue:
        report_lines.append("  [+] 所有高危权限引用均伴随 checkSelfPermission 调用（或未直接引用）")
    report_lines.append("")

    # 3. 检查 onRequestPermissionsResult 中是否处理拒绝
    report_lines.append("--- 3. 权限拒绝处理检查 ---")
    # 简单搜索是否存在 shouldShowRequestPermissionRationale
    smali_dir = os.path.join(unpack_dir, 'smali')
    rational_count = 0
    if os.path.exists(smali_dir):
        for root_dir, dirs, files in os.walk(smali_dir):
            for file in files:
                if file.endswith('.smali'):
                    with open(os.path.join(root_dir, file), 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        if 'shouldShowRequestPermissionRationale' in content:
                            rational_count += 1
    if rational_count > 0:
        report_lines.append(f"  发现 {rational_count} 处 shouldShowRequestPermissionRationale 调用")
        report_lines.append("  [+] 应用至少部分处理了权限被拒绝的情况。")
    else:
        report_lines.append("  [警告] 未检测到 shouldShowRequestPermissionRationale 调用")
        report_lines.append("         用户拒绝权限后应用可能直接崩溃或黑屏。")
    report_lines.append("")

    # 4. 综合建议
    report_lines.append("--- 4. 综合建议 ---")
    if target_sdk:
        target_int = int(target_sdk)
        if target_int >= 23:
            report_lines.append(f"  targetSdkVersion = {target_int}，必须完整适配运行时权限。")
            if has_issue:
                report_lines.append("  ⚠️ 存在未保护的权限调用，建议补充 checkSelfPermission 和 requestPermissions。")
            else:
                report_lines.append("  ✅ 代码中已使用权限检查，但需人工验证所有路径。")
        else:
            report_lines.append(f"  targetSdkVersion = {target_int}（低于 23），使用旧授权模型。")
            report_lines.append("  但用户仍可在设置中取消权限，建议升级 targetSdkVersion 并适配。")
    else:
        report_lines.append("  targetSdkVersion 未知，建议升级至 31+ 并全面适配。")

    # 引用参考资料
    report_lines.append("")
    report_lines.append("(分析基于 aapt dump badging 方法[4](@ref)[6](@ref) 及 Smali 静态扫描)")
    return '\n'.join(report_lines)

def main():
    if len(sys.argv) < 2:
        print("用法: python apk_deep_analysis.py <apk_path> [unpack_dir]")
        sys.exit(1)

    apk_path = sys.argv[1]
    if not os.path.exists(apk_path):
        print(f"错误: APK 文件不存在: {apk_path}")
        sys.exit(1)

    apk_name = os.path.splitext(os.path.basename(apk_path))[0]
    default_unpack = os.path.join(os.path.dirname(apk_path), 'unpack', apk_name)
    unpack_dir = sys.argv[2] if len(sys.argv) > 2 else default_unpack
    if not os.path.exists(unpack_dir):
        print(f"警告: 反编译目录 {unpack_dir} 不存在，将尝试仅使用 aapt 分析")
        unpack_dir = None   # 没有反编译目录，只做 aapt 部分

    report = generate_deep_report(apk_path, unpack_dir)
    output_file = os.path.join(os.path.dirname(apk_path), f"{apk_name}_deep_analysis.txt")
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(report)
    print(f"深度分析报告已生成: {output_file}")
    print(report)

if __name__ == '__main__':
    main()
