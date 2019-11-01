/* Copyright (c) 2010-2015, 2018 The Linux Foundation. All rights reserved.
 * Copyright (C) 2015 Linaro Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#ifndef __QCOM_SCM_H
#define __QCOM_SCM_H

#define QTI_SCM_SVC_BOOT	0x1
#define QTI_SCM_CMD_USER_READ	0x17
#define QTI_SCM_CMD_USER_WRITE	0x16
#define QTI_SCM_SVC_IO_ACCESS	0x5
#define QTI_SCM_IO_WRITE	0x2

extern int qcom_scm_set_cold_boot_addr(void *entry, const cpumask_t *cpus);
extern int qcom_scm_set_warm_boot_addr(void *entry, const cpumask_t *cpus);

#define QCOM_SCM_HDCP_MAX_REQ_CNT	5

struct qcom_scm_hdcp_req {
	u32 addr;
	u32 val;
};

extern bool qcom_scm_hdcp_available(void);
extern int qcom_scm_hdcp_req(struct qcom_scm_hdcp_req *req, u32 req_cnt,
		u32 *resp);

#define QCOM_SCM_CPU_PWR_DOWN_L2_ON	0x0
#define QCOM_SCM_CPU_PWR_DOWN_L2_OFF	0x1

extern void qcom_scm_cpu_power_down(u32 flags);

#define QCOM_SCM_VERSION(major, minor) (((major) << 16) | ((minor) & 0xFF))

extern u32 qcom_scm_get_version(void);

#define SCM_SVC_UTIL		0x3
#define SCM_CMD_SET_REGSAVE	0x2

extern int qcom_scm_regsave(u32 svc_id, u32 cmd_id);

int qcom_scm_call(u32 svc_id, u32 cmd_id, const void *cmd_buf,
			size_t cmd_len, void *resp_buf, size_t resp_len);

s32 qti_scm_call_atomic2(u32 svc, u32 cmd, u32 arg1, u32 arg2);


#endif
