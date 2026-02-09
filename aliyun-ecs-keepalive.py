#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
阿里云 ECS 抢占式实例保活脚本

通过 CDT API 查询当前流量，低于阈值则启动实例，超过阈值则停止实例。
适合通过 crontab 定时调用。

依赖安装: pip install aliyun-python-sdk-core aliyun-python-sdk-ecs
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path

# 加载脚本同目录下的 .env 文件
_env_path = Path(__file__).resolve().parent / ".env"
if _env_path.is_file():
    with open(_env_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _key, _, _value = _line.partition("=")
                os.environ.setdefault(_key.strip(), _value.strip())

from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.request import CommonRequest
from aliyunsdkecs.request.v20140526 import (
    DescribeInstancesRequest,
    StartInstancesRequest,
    StopInstancesRequest,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(
        description="阿里云 ECS 抢占式实例保活脚本 - 基于 CDT 流量自动启停实例",
    )

    parser.add_argument(
        "--access-key-id",
        default=os.environ.get("ALIYUN_ACCESS_KEY_ID"),
        help="阿里云 AccessKey ID (环境变量: ALIYUN_ACCESS_KEY_ID)",
    )
    parser.add_argument(
        "--access-key-secret",
        default=os.environ.get("ALIYUN_ACCESS_KEY_SECRET"),
        help="阿里云 AccessKey Secret (环境变量: ALIYUN_ACCESS_KEY_SECRET)",
    )
    parser.add_argument(
        "--region-id",
        default=os.environ.get("ALIYUN_REGION_ID", "cn-hongkong"),
        help="区域 ID (环境变量: ALIYUN_REGION_ID, 默认: cn-hongkong)",
    )
    parser.add_argument(
        "--instance-id",
        default=os.environ.get("ALIYUN_ECS_INSTANCE_ID"),
        help="ECS 实例 ID (环境变量: ALIYUN_ECS_INSTANCE_ID)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=float(os.environ.get("TRAFFIC_THRESHOLD_GB", "180")),
        help="流量阈值 GB (环境变量: TRAFFIC_THRESHOLD_GB, 默认: 180)",
    )

    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        "--check",
        action="store_true",
        help="仅查询流量和实例状态，不执行启停操作",
    )
    action.add_argument(
        "--start",
        action="store_true",
        help="强制启动实例（忽略流量判断）",
    )
    action.add_argument(
        "--stop",
        action="store_true",
        help="强制停止实例（忽略流量判断）",
    )

    args = parser.parse_args()

    if not args.access_key_id:
        parser.error("必须提供 AccessKey ID (--access-key-id 或 ALIYUN_ACCESS_KEY_ID)")
    if not args.access_key_secret:
        parser.error("必须提供 AccessKey Secret (--access-key-secret 或 ALIYUN_ACCESS_KEY_SECRET)")
    if not args.instance_id:
        parser.error("必须提供 ECS 实例 ID (--instance-id 或 ALIYUN_ECS_INSTANCE_ID)")

    return args


def create_client(access_key_id, access_key_secret, region_id):
    try:
        client = AcsClient(access_key_id, access_key_secret, region_id)
        logger.info("AcsClient 初始化成功")
        return client
    except Exception as e:
        logger.error(f"AcsClient 初始化失败: {e}")
        sys.exit(1)


def get_total_traffic_gb(client):
    """查询 CDT 互联网流量总量 (GB)"""
    request = CommonRequest()
    request.set_domain("cdt.aliyuncs.com")
    request.set_version("2021-08-13")
    request.set_action_name("ListCdtInternetTraffic")
    request.set_method("POST")

    try:
        response = client.do_action_with_exception(request)
        response_json = json.loads(response.decode("utf-8"))

        total_bytes = sum(
            d.get("Traffic", 0)
            for d in response_json.get("TrafficDetails", [])
        )
        total_gb = total_bytes / (1024**3)

        logger.info(f"当前总互联网流量: {total_gb:.2f} GB")
        return total_gb
    except Exception as e:
        logger.error(f"获取 CDT 流量失败: {e}")
        sys.exit(1)


def get_ecs_status(client, instance_id):
    """查询 ECS 实例状态"""
    try:
        request = DescribeInstancesRequest.DescribeInstancesRequest()
        request.set_InstanceIds([instance_id])
        response = client.do_action_with_exception(request)
        response_json = json.loads(response.decode("utf-8"))

        instances = response_json.get("Instances", {}).get("Instance", [])
        if not instances:
            logger.error("未找到该 ECS 实例信息")
            return None

        status = instances[0].get("Status")
        logger.info(f"ECS 实例 {instance_id} 当前状态: {status}")
        return status
    except Exception as e:
        logger.error(f"获取 ECS 实例状态失败: {e}")
        return None


def ecs_start(client, instance_id):
    """启动 ECS 实例"""
    status = get_ecs_status(client, instance_id)
    if status == "Running":
        logger.info(f"ECS 实例 {instance_id} 已经是运行状态，无需启动")
        return

    try:
        request = StartInstancesRequest.StartInstancesRequest()
        request.set_InstanceIds([instance_id])
        request.set_accept_format("json")

        response = client.do_action_with_exception(request)
        logger.info(f"ECS 启动响应: {response.decode('utf-8')}")
    except Exception as e:
        logger.error(f"启动 ECS 实例失败: {e}")


def ecs_stop(client, instance_id):
    """停止 ECS 实例"""
    status = get_ecs_status(client, instance_id)
    if status == "Stopped":
        logger.info(f"ECS 实例 {instance_id} 已经是停止状态，无需再次停止")
        return

    try:
        request = StopInstancesRequest.StopInstancesRequest()
        request.set_InstanceIds([instance_id])
        request.set_ForceStop(False)
        request.set_accept_format("json")

        response = client.do_action_with_exception(request)
        logger.info(f"ECS 停止响应: {response.decode('utf-8')}")
    except Exception as e:
        logger.error(f"停止 ECS 实例失败: {e}")


def main():
    args = parse_args()
    client = create_client(args.access_key_id, args.access_key_secret, args.region_id)

    if args.start:
        logger.info("手动强制启动模式")
        ecs_start(client, args.instance_id)
        return

    if args.stop:
        logger.info("手动强制停止模式")
        ecs_stop(client, args.instance_id)
        return

    total_gb = get_total_traffic_gb(client)
    status = get_ecs_status(client, args.instance_id)

    if args.check:
        logger.info(
            f"[检查模式] 流量: {total_gb:.2f}/{args.threshold} GB, "
            f"实例状态: {status}, "
            f"{'低于阈值 → 应启动' if total_gb < args.threshold else '超过阈值 → 应停止'}"
        )
        return

    if total_gb < args.threshold:
        logger.info(
            f"流量 {total_gb:.2f} GB < 阈值 {args.threshold} GB，尝试启动 ECS"
        )
        ecs_start(client, args.instance_id)
    else:
        logger.info(
            f"流量 {total_gb:.2f} GB >= 阈值 {args.threshold} GB，尝试停止 ECS"
        )
        ecs_stop(client, args.instance_id)

    logger.info("脚本执行完毕")


if __name__ == "__main__":
    main()
