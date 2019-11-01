/*
 * SPDX-License-Identifier: ISC
 * Copyright (c) 2018, The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/irqdomain.h>
#include <linux/interrupt.h>
#include <linux/irqreturn.h>
#include <linux/of.h>
#include <linux/mm.h>
#include <linux/irq.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>
#include <linux/of_device.h>
#include <linux/debugfs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <asm/outercache.h>
#include <asm/cacheflush.h>
#include <linux/qcom_scm.h>

static int panic_on_xpu_violation;

#define TZBUF_MAX_SIZE	4096

struct tzbsp_info {
	void *addr;
	int irq;
	uint32_t reg_val;
	struct mutex mutex_lock;
	struct dentry *tz_dentry;
};

static ssize_t tz_usr_iface_read(struct file *file, char __user *user_buf,
						size_t size, loff_t *pos)
{
	struct tzbsp_info *tzbsp_info = (struct tzbsp_info *)file->private_data;
	int ret;

	memset(tzbsp_info->addr, 0x0, TZBUF_MAX_SIZE);

	ret = qcom_scm_call(QTI_SCM_SVC_BOOT, QTI_SCM_CMD_USER_READ, NULL, 0,
					tzbsp_info->addr, TZBUF_MAX_SIZE);

	if (ret) {
		pr_info("%s: SCM Call failed, ret = %d\n", __func__, ret);
		return ret;
	}

	return simple_read_from_buffer(user_buf, size, pos,
				(void *)tzbsp_info->addr, TZBUF_MAX_SIZE);
}

static ssize_t tz_usr_iface_write(struct file *file,
			const char __user *user_buf, size_t size, loff_t *pos)
{
	int ret;
	struct tzbsp_info *tzbsp_info = (struct tzbsp_info *)file->private_data;
	struct req_buf {
		uint32_t addr;
		uint32_t size;
	} req_buf;

	memset(tzbsp_info->addr, 0x0, TZBUF_MAX_SIZE);

	ret = simple_write_to_buffer((void *)tzbsp_info->addr,
					TZBUF_MAX_SIZE, pos, user_buf, size);
	if (ret <= 0) {
		pr_err("%s: copy failed from user buffer to kernel buffer\n",
								__func__);
		ret = -EIO;
		goto exit;
	}

	/*
	 * Flush the buffer so that the secure world sees
	 * the correct data.
	 */
	__cpuc_flush_dcache_area(tzbsp_info->addr, TZBUF_MAX_SIZE);
	outer_flush_range(virt_to_phys(tzbsp_info->addr), TZBUF_MAX_SIZE);

	req_buf.addr = virt_to_phys(tzbsp_info->addr);
	req_buf.size = TZBUF_MAX_SIZE;

	ret = qcom_scm_call(QTI_SCM_SVC_BOOT, QTI_SCM_CMD_USER_WRITE,
			&req_buf, sizeof(struct req_buf), NULL, 0);
	if (ret) {
		pr_info("%s: SCM call failed, ret = %d\n", __func__, ret);
		goto exit;
	}
	ret = size;
exit:
	return ret;
}

static int tz_usr_iface_open(struct inode *inode, struct file *file)
{

	struct tzbsp_info *tzbsp_info;

	file->private_data = inode->i_private;
	tzbsp_info = (struct tzbsp_info *)file->private_data;
	mutex_lock(&tzbsp_info->mutex_lock);

	return 0;
}

static int tz_usr_iface_release(struct inode *inode, struct file *file)
{
	struct tzbsp_info *tzbsp_info;

	tzbsp_info = (struct tzbsp_info *)file->private_data;
	mutex_unlock(&tzbsp_info->mutex_lock);

	return 0;
}

static const struct file_operations tz_usr_iface_fops = {
	.open = tz_usr_iface_open,
	.read = tz_usr_iface_read,
	.write = tz_usr_iface_write,
	.release = tz_usr_iface_release,
};

static irqreturn_t tzerr_irq(int irq, void *data)
{
	if (panic_on_xpu_violation)
		panic("XPU Violation Occurred\n");
	else
		pr_emerg("WARN: XPU Access Violation!!!\n");

	return IRQ_HANDLED;
}

static const struct of_device_id qti_tz_usr_iface_of_match[] = {
	{ .compatible = "qti,tz-usr-iface" },
	{}
};
MODULE_DEVICE_TABLE(of, qti_tz_usr_iface_of_match);

static int qti_tz_usr_iface_probe(struct platform_device *pdev)
{

	int ret;
	struct device_node *np;
	struct device_node *cnp;
	struct dentry *tz_file;
	struct tzbsp_info *tzbsp_info;
	struct page *page;
	struct irq_desc *desc;

	np = of_node_get(pdev->dev.of_node);
	if (!np) {
		dev_err(&pdev->dev, "device node is not found\n");
		return -ENOENT;
	}

	tzbsp_info = kzalloc(sizeof(struct tzbsp_info), GFP_KERNEL);
	if (tzbsp_info == NULL)
		return -ENOMEM;

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		ret = -ENOMEM;
		goto free_mem;
	}

	tzbsp_info->addr = page_address(page);

	mutex_init(&tzbsp_info->mutex_lock);

	tzbsp_info->tz_dentry = debugfs_create_dir("tz", NULL);
	if (IS_ERR_OR_NULL(tzbsp_info->tz_dentry)) {
		dev_err(&pdev->dev, "Failed to create debugfs entry\n");
		ret = -EIO;
		goto free_page;
	}

	tz_file = debugfs_create_file("tz_usr_iface", 0644,
					tzbsp_info->tz_dentry, tzbsp_info,
					&tz_usr_iface_fops);
	if (IS_ERR_OR_NULL(tz_file)) {
		dev_err(&pdev->dev, "Failed to create debugfs file\n");
		ret = -EIO;
		goto remove_debugfs;
	}

	ret = of_property_read_bool(np, "qti,xpu-interrupt-support");
	if (!ret) {
		dev_info(&pdev->dev, "XPU interrupt support property is not configured\n");
		ret = 0;
		goto exit;
	}

	for_each_available_child_of_node(np, cnp) {

		ret = of_property_read_u32(cnp, "reg_val",
							&tzbsp_info->reg_val);
		if (ret) {
			dev_err(&pdev->dev, "reg_val property not found\n");
			goto remove_debugfs;
		}

		tzbsp_info->irq = of_irq_get(cnp, 0);
		if (tzbsp_info->irq <= 0) {
			dev_err(&pdev->dev, "Unable to get the IRQ\n");
			goto remove_debugfs;
		}

		desc = irq_to_desc(tzbsp_info->irq);

		/* Pass the HW IRQ number to TZ */
		ret = qti_scm_call_atomic2(QTI_SCM_SVC_IO_ACCESS,
						QTI_SCM_IO_WRITE,
						tzbsp_info->reg_val,
						desc->irq_data.hwirq);
		if (ret) {
			dev_err(&pdev->dev, "Failed to register IRQ with TZ, ret = %d\n",
									ret);
			goto remove_debugfs;
		}

		ret = devm_request_irq(&pdev->dev, tzbsp_info->irq, tzerr_irq,
				IRQF_ONESHOT, "XPU Violation", NULL);

		if (ret) {
			dev_err(&pdev->dev, "Error in registering IRQ handler, ret = %d\n",
									ret);
			goto remove_debugfs;
		}

		ret = of_property_read_bool(cnp, "qti,panic-on-xpu-violation");
		if (ret) {
			panic_on_xpu_violation = 1;
			dev_info(&pdev->dev, "Will panic on XPU violation, since the panic_on_xpu_violation property is set\n");
		} else {
			dev_info(&pdev->dev, "Will log the XPU violation message, since the panic-on-xpu-violation property is not set\n");
		}
	}

	platform_set_drvdata(pdev, tzbsp_info);

	return 0;

remove_debugfs:
	debugfs_remove_recursive(tzbsp_info->tz_dentry);
free_page:
	__free_pages(virt_to_page(tzbsp_info->addr), 0);
free_mem:
	kfree(tzbsp_info);
exit:
	return ret;
}

static int qti_tz_usr_iface_remove(struct platform_device *pdev)
{
	struct tzbsp_info *tzbsp_info = platform_get_drvdata(pdev);

	debugfs_remove_recursive(tzbsp_info->tz_dentry);
	__free_pages(virt_to_page(tzbsp_info->addr), 0);
	kfree(tzbsp_info);
	return 0;
}

static struct platform_driver qti_tz_usr_iface_driver = {
	.probe = qti_tz_usr_iface_probe,
	.remove = qti_tz_usr_iface_remove,
	.driver  = {
		.name  = "qti_tz_usr_iface",
		.of_match_table = qti_tz_usr_iface_of_match,
	},
};

module_platform_driver(qti_tz_usr_iface_driver);
