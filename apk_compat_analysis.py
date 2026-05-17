# -*- coding: utf-8 -*-
"""
补充脚本：分析 APK 的 Android 6.0+ 权限兼容性
用法：python apk_compat_analysis.py <apk_path> [unpack_dir]
- apk_path: 原始 APK 文件路径（用于获取基本信息）
- unpack_dir: 可选，ApkTool.py 反编译后的目录（默认为 apk_path 同目录下的 unpack/<apk_name>）
输出：在 apk_path 同目录下生成 <apk_name>_compat.txt 或追加到原有分析文件
"""

import os
import sys
import xml.etree.ElementTree as ET
import re

def get_apk_name(apk_path):
    """从 APK 路径提取不带后缀的文件名"""
    return os.path.splitext(os.path.basename(apk_path))

def parse_android_manifest(unpack_dir):
    """解析反编译后的 AndroidManifest.xml，返回关键信息字典"""
    manifest_path = os.path.join(unpack_dir, 'AndroidManifest.xml')
    if not os.path.exists(manifest_path):
        return None

    tree = ET.parse(manifest_path)
    root = tree.getroot()

    # 命名空间处理（AndroidManifest.xml 通常使用 android: 命名空间）
    ns = {'android': 'http://schemas.android.com/apk/res/android'}

    # 获取包名、版本信息
    package = root.get('package', '')
    version_code = root.get('{http://schemas.android.com/apk/res/android}versionCode', '')
    version_name = root.get('{http://schemas.android.com/apk/res/android}versionName', '')

    # 获取 minSdkVersion 和 targetSdkVersion（可能在 <uses-sdk> 标签中）
    min_sdk = ''
    target_sdk = ''
    uses_sdk = root.find('uses-sdk')
    if uses_sdk is not None:
        min_sdk = uses_sdk.get('{http://schemas.android.com/apk/res/android}minSdkVersion', '')
        target_sdk = uses_sdk.get('{http://schemas.android.com/apk/res/android}targetSdkVersion', '')

    # 获取所有权限声明
    permissions = []
    for perm in root.findall('uses-permission'):
        perm_name = perm.get('{http://schemas.android.com/apk/res/android}name', '')
        if perm_name:
            permissions.append(perm_name)

    # 获取 maxSdkVersion（可选）
    max_sdk = ''
    if uses_sdk is not None:
        max_sdk = uses_sdk.get('{http://schemas.android.com/apk/res/android}maxSdkVersion', '')

    return {
        'package': package,
        'version_code': version_code,
        'version_name': version_name,
        'min_sdk': min_sdk,
        'target_sdk': target_sdk,
        'max_sdk': max_sdk,
        'permissions': permissions
    }

def scan_smali_for_runtime_permissions(unpack_dir):
    """扫描 smali 目录，查找运行时权限相关调用"""
    smali_dir = os.path.join(unpack_dir, 'smali')
    if not os.path.exists(smali_dir):
        return []

    # 运行时权限相关的方法签名（常见模式）
    patterns = [
        r'checkSelfPermission',          # ContextCompat.checkSelfPermission
        r'requestPermissions',            # Activity.requestPermissions
        r'shouldShowRequestPermissionRationale',  # 权限解释
        r'onRequestPermissionsResult',    # 权限结果回调
        r'PERMISSION_GRANTED',            # 权限常量
        r'PERMISSION_DENIED',
        r'Manifest\.permission\.',        # 引用具体权限
    ]

    findings = []
    for root_dir, dirs, files in os.walk(smali_dir):
        for file in files:
            if file.endswith('.smali'):
                filepath = os.path.join(root_dir, file)
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    for pattern in patterns:
                        if re.search(pattern, content):
                            # 提取所在文件名（相对路径）
                            rel_path = os.path.relpath(filepath, smali_dir)
                            findings.append((pattern, rel_path))
                            break  # 一个文件只记录一次
    return findings

def check_high_risk_permissions(permissions):
    """检查是否声明了需要运行时权限的高危权限"""
    dangerous_permissions = [
        'android.permission.READ_CONTACTS',
        'android.permission.WRITE_CONTACTS',
        'android.permission.ACCESS_FINE_LOCATION',
        'android.permission.ACCESS_COARSE_LOCATION',
        'android.permission.CAMERA',
        'android.permission.RECORD_AUDIO',
        'android.permission.READ_CALENDAR',
        'android.permission.WRITE_CALENDAR',
        'android.permission.READ_EXTERNAL_STORAGE',
        'android.permission.WRITE_EXTERNAL_STORAGE',
        'android.permission.READ_PHONE_STATE',
        'android.permission.SEND_SMS',
        'android.permission.RECEIVE_SMS',
        'android.permission.READ_SMS',
        'android.permission.BODY_SENSORS',
    ]
    high_risk = [p for p in permissions if p in dangerous_permissions]
    return high_risk

def generate_report(apk_path, unpack_dir):
    """生成兼容性分析报告"""
    apk_name = get_apk_name(apk_path)
    report_lines = []
    report_lines.append(f"===== APK 权限兼容性分析报告 =====")
    report_lines.append(f"分析时间: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append(f"APK 文件: {apk_path}")
    report_lines.append("")

    # 1. 解析 AndroidManifest
    manifest_info = parse_android_manifest(unpack_dir)
    if manifest_info is None:
        report_lines.append("[错误] 无法找到 AndroidManifest.xml，请确认反编译目录正确。")
    else:
        report_lines.append("--- 基本信息 ---")
        report_lines.append(f"包名: {manifest_info['package']}")
        report_lines.append(f"版本号: {manifest_info['version_code']} ({manifest_info['version_name']})")
        report_lines.append(f"minSdkVersion: {manifest_info['min_sdk'] or '未设置'}")
        report_lines.append(f"targetSdkVersion: {manifest_info['target_sdk'] or '未设置'}")
        report_lines.append(f"maxSdkVersion: {manifest_info['max_sdk'] or '未设置'}")
        report_lines.append("")

        # 2. 权限列表
        report_lines.append("--- 声明的权限 (共 {} 个) ---".format(len(manifest_info['permissions'])))
        for perm in manifest_info['permissions']:
            report_lines.append(f"  {perm}")
        report_lines.append("")

        # 3. 高危权限检查
        high_risk = check_high_risk_permissions(manifest_info['permissions'])
        if high_risk:
            report_lines.append("--- 高危权限 (需要运行时申请) ---")
            for p in high_risk:
                report_lines.append(f"  {p}")
            report_lines.append("")

        # 4. targetSdkVersion 风险判断
        target_sdk = manifest_info.get('target_sdk', '')
        if target_sdk and target_sdk.isdigit():
            target_int = int(target_sdk)
            if target_int >= 23:
                report_lines.append("[风险提示] targetSdkVersion >= 23，应用必须适配运行时权限模型。")
                report_lines.append("          如果未正确实现运行时权限申请，在 Android 6.0+ 上可能闪退。")
            else:
                report_lines.append("[提示] targetSdkVersion < 23，应用仍使用旧权限模型，")
                report_lines.append("       在 Android 6.0+ 上安装时仍会一次性授予权限，但可能被用户手动关闭。")
        else:
            report_lines.append("[警告] 无法获取 targetSdkVersion，请检查 AndroidManifest.xml。")
        report_lines.append("")

    # 5. 扫描 smali 中的运行时权限调用
    report_lines.append("--- 运行时权限 API 使用检测 ---")
    findings = scan_smali_for_runtime_permissions(unpack_dir)
    if findings:
        report_lines.append("发现以下运行时权限相关调用（文件路径相对于 smali 目录）：")
        for pattern, file_rel in findings:
            report_lines.append(f"  - 模式 '{pattern}' 出现在: {file_rel}")
        report_lines.append("")
        report_lines.append("[结论] 应用已使用运行时权限 API，但需进一步检查逻辑是否正确。")
    else:
        report_lines.append("未检测到运行时权限 API 调用。")
        if target_sdk and target_sdk.isdigit() and int(target_sdk) >= 23:
            report_lines.append("[严重警告] targetSdkVersion >= 23 但未使用运行时权限 API，")
            report_lines.append("           应用在高版本 Android 上极大概率闪退！")
        else:
            report_lines.append("[提示] 应用可能未适配运行时权限，但若 targetSdkVersion < 23 则暂时安全。")
    report_lines.append("")

    # 6. 总结建议
    report_lines.append("--- 总结与建议 ---")
    if target_sdk and target_sdk.isdigit() and int(target_sdk) >= 23 and not findings:
        report_lines.append("1. 必须实现运行时权限申请逻辑（checkSelfPermission + requestPermissions）。")
        report_lines.append("2. 检查所有高危权限的使用场景，添加权限请求回调。")
        report_lines.append("3. 建议将 targetSdkVersion 更新至最新，并全面测试。")
    elif target_sdk and target_sdk.isdigit() and int(target_sdk) >= 23 and findings:
        report_lines.append("1. 已检测到运行时权限 API 使用，但需人工验证逻辑完整性。")
        report_lines.append("2. 确保每个高危权限都有对应的请求和结果处理。")
        report_lines.append("3. 检查是否遗漏了某些权限的运行时申请。")
    else:
        report_lines.append("1. 当前 targetSdkVersion 较低，但建议逐步适配运行时权限。")
        report_lines.append("2. 注意：即使 targetSdkVersion < 23，用户仍可在设置中关闭权限。")
    report_lines.append("")

    return '\n'.join(report_lines)

def main():
    if len(sys.argv) < 2:
        print("用法: python apk_compat_analysis.py <apk_path> [unpack_dir]")
        sys.exit(1)

    apk_path = sys.argv[1]          # 这是正确的：取第一个实际参数
    if not os.path.exists(apk_path):
        print(f"错误: APK 文件不存在: {apk_path}")
        sys.exit(1)

    apk_name = os.path.splitext(os.path.basename(apk_path))[0]  # 注意只取文件名（不含扩展名）
    # 默认反编译目录：apk_path 所在目录下的 unpack/<apk_name>
    default_unpack = os.path.join(os.path.dirname(apk_path), 'unpack', apk_name)
    unpack_dir = sys.argv[2] if len(sys.argv) > 2 else default_unpack

    if not os.path.exists(unpack_dir):
        print(f"错误: 反编译目录不存在: {unpack_dir}")
        print("请先使用 ApkTool.py 的 -analyse 或 -unpack 命令生成反编译目录。")
        sys.exit(1)

    report = generate_report(apk_path, unpack_dir)

    # 输出到文件：与原有分析文件同目录，命名为 <apk_name>_compat.txt
    output_file = os.path.join(os.path.dirname(apk_path), f"{apk_name}_compat.txt")
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(report)

    print(f"分析报告已生成: {output_file}")
    print(report)

if __name__ == '__main__':
    main()
