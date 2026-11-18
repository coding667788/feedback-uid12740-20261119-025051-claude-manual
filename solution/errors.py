"""错误码定义。

输入类错误统一抛出 :class:`AuditError`，CLI 捕获后以退出码 2 输出 JSON 诊断；
搜索不到合法计划不属于输入错误，结果状态为 ``no_plan``，退出码为 0。
"""

from __future__ import annotations


class AuditError(Exception):
    """所有可预期的输入/结构错误的基类。"""

    code = "E_INTERNAL"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code


# 错误码表（README 同步说明）：
ERROR_CODES = {
    "E_IO": "输入文件无法读取或输出路径不可写",
    "E_JSON": "输入不是合法 JSON，或顶层结构与声明的 schema 不符",
    "E_SCHEMA": "字段缺失、类型错误、取值非法",
    "E_DOMAIN": "端口、协议、服务/组/实例引用或区间声明不合法",
    "E_DAG_CYCLE": "部署组依赖图存在环或引用了不存在的组",
    "E_RULE": "规则选择器、动作或区间不合法，或规则 id 重复",
    "E_INITIAL": "初始状态（无组切换）即违反必需/禁止连通性约束",
    "E_FINAL": "全量目标状态违反必需/禁止连通性约束，计划不可能存在",
}


def raise_error(code: str, message: str) -> None:
    raise AuditError(message, code=code)
