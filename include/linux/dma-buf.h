/*
 * Header file for dma buffer sharing framework.
 *
 * Copyright(C) 2011 Linaro Limited. All rights reserved.
 * Author: Sumit Semwal <sumit.semwal@ti.com>
 *
 * Many thanks to linaro-mm-sig list, and specially
 * Arnd Bergmann <arnd@arndb.de>, Rob Clark <rob@ti.com> and
 * Daniel Vetter <daniel@ffwll.ch> for their support in creation and
 * refining of this idea.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __DMA_BUF_H__
#define __DMA_BUF_H__

#include <linux/file.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <linux/list.h>
#include <linux/dma-mapping.h>
#include <linux/fs.h>
#include <linux/dma-fence.h>
#include <linux/wait.h>

struct device;
struct dma_buf;
struct dma_buf_attachment;

/**
 * struct dma_buf_ops - operations possible on struct dma_buf
 * @begin_cpu_access: [optional] called before cpu access to invalidate cpu
 * 		      caches and allocate backing storage (if not yet done)
 * 		      respectively pin the object into memory.
 * @end_cpu_access: [optional] called after cpu access to flush caches.
 * @kmap_atomic: maps a page from the buffer into kernel address
 * 		 space, users may not block until the subsequent unmap call.
 * 		 This callback must not sleep.
 * @kunmap_atomic: [optional] unmaps a atomically mapped page from the buffer.
 * 		   This Callback must not sleep.
 * @kmap: maps a page from the buffer into kernel address space.
 * @kunmap: [optional] unmaps a page from the buffer.
 * @mmap: used to expose the backing storage to userspace. Note that the
 * 	  mapping needs to be coherent - if the exporter doesn't directly
 * 	  support this, it needs to fake coherency by shooting down any ptes
 * 	  when transitioning away from the cpu domain.
 * @vmap: [optional] creates a virtual mapping for the buffer into kernel
 *	  address space. Same restrictions as for vmap and friends apply.
 * @vunmap: [optional] unmaps a vmap from the buffer
 */
struct dma_buf_ops {
	/**
	 * @attach:
	 *
	 * This is called from dma_buf_attach() to make sure that a given
	 * &device can access the provided &dma_buf. Exporters which support
	 * buffer objects in special locations like VRAM or device-specific
	 * carveout areas should check whether the buffer could be move to
	 * system memory (or directly accessed by the provided device), and
	 * otherwise need to fail the attach operation.
	 *
	 * The exporter should also in general check whether the current
	 * allocation fullfills the DMA constraints of the new device. If this
	 * is not the case, and the allocation cannot be moved, it should also
	 * fail the attach operation.
	 *
	 * Any exporter-private housekeeping data can be stored in the priv
	 * pointer of &dma_buf_attachment structure.
	 *
	 * This callback is optional.
	 *
	 * Returns:
	 *
	 * 0 on success, negative error code on failure. It might return -EBUSY
	 * to signal that backing storage is already allocated and incompatible
	 * with the requirements of requesting device.
	 */
	int (*attach)(struct dma_buf *, struct device *,
		      struct dma_buf_attachment *);

	/**
	 * @detach:
	 *
	 * This is called by dma_buf_detach() to release a &dma_buf_attachment.
	 * Provided so that exporters can clean up any housekeeping for an
	 * &dma_buf_attachment.
	 *
	 * This callback is optional.
	 */
	void (*detach)(struct dma_buf *, struct dma_buf_attachment *);

	/**
	 * @map_dma_buf:
	 *
	 * This is called by dma_buf_map_attachment() and is used to map a
	 * shared &dma_buf into device address space, and it is mandatory. It
	 * can only be called if @attach has been called successfully. This
	 * essentially pins the DMA buffer into place, and it cannot be moved
	 * any more
	 *
	 * This call may sleep, e.g. when the backing storage first needs to be
	 * allocated, or moved to a location suitable for all currently attached
	 * devices.
	 *
	 * Note that any specific buffer attributes required for this function
	 * should get added to device_dma_parameters accessible via
	 * device->dma_params from the &dma_buf_attachment. The @attach callback
	 * should also check these constraints.
	 *
	 * If this is being called for the first time, the exporter can now
	 * choose to scan through the list of attachments for this buffer,
	 * collate the requirements of the attached devices, and choose an
	 * appropriate backing storage for the buffer.
	 *
	 * Based on enum dma_data_direction, it might be possible to have
	 * multiple users accessing at the same time (for reading, maybe), or
	 * any other kind of sharing that the exporter might wish to make
	 * available to buffer-users.
	 *
	 * Returns:
	 *
	 * A &sg_table scatter list of or the backing storage of the DMA buffer,
	 * already mapped into the device address space of the &device attached
	 * with the provided &dma_buf_attachment.
	 *
	 * On failure, returns a negative error value wrapped into a pointer.
	 * May also return -EINTR when a signal was received while being
	 * blocked.
	 */
	struct sg_table * (*map_dma_buf)(struct dma_buf_attachment *,
					 enum dma_data_direction);
	/**
	 * @unmap_dma_buf:
	 *
	 * This is called by dma_buf_unmap_attachment() and should unmap and
	 * release the &sg_table allocated in @map_dma_buf, and it is mandatory.
	 * It should also unpin the backing storage if this is the last mapping
	 * of the DMA buffer, it the exporter supports backing storage
	 * migration.
	 */
	void (*unmap_dma_buf)(struct dma_buf_attachment *,
			      struct sg_table *,
			      enum dma_data_direction);

	/* TODO: Add try_map_dma_buf version, to return immed with -EBUSY
	 * if the call would block.
	 */

	/**
	 * @release:
	 *
	 * Called after the last dma_buf_put to release the &dma_buf, and
	 * mandatory.
	 */
	void (*release)(struct dma_buf *);

	int (*begin_cpu_access)(struct dma_buf *, enum dma_data_direction);
	int (*end_cpu_access)(struct dma_buf *, enum dma_data_direction);
	void *(*kmap_atomic)(struct dma_buf *, unsigned long);
	void (*kunmap_atomic)(struct dma_buf *, unsigned long, void *);
	void *(*kmap)(struct dma_buf *, unsigned long);
	void (*kunmap)(struct dma_buf *, unsigned long, void *);

	int (*mmap)(struct dma_buf *, struct vm_area_struct *vma);

	void *(*vmap)(struct dma_buf *);
	void (*vunmap)(struct dma_buf *, void *vaddr);

	void *(*get_drvdata)(struct dma_buf *, struct device *);
	int (*set_drvdata)(struct dma_buf *, struct device *, void *priv,
			   void (*)(void *));
};

/**
 * struct dma_buf - shared buffer object
 * @size: size of the buffer
 * @file: file pointer used for sharing buffers across, and for refcounting.
 * @attachments: list of dma_buf_attachment that denotes all devices attached.
 * @ops: dma_buf_ops associated with this buffer object.
 * @exp_name: name of the exporter; useful for debugging.
 * @list_node: node for dma_buf accounting and debugging.
 * @priv: exporter specific private data for this buffer object.
 * @resv: reservation object linked to this dma-buf
 *
 * This represents a shared buffer, created by calling dma_buf_export(). The
 * userspace representation is a normal file descriptor, which can be created by
 * calling dma_buf_fd().
 *
 * Shared dma buffers are reference counted using dma_buf_put() and
 * get_dma_buf().
 *
 * Device DMA access is handled by the separate struct &dma_buf_attachment.
 */
struct dma_buf {
	size_t size;
	struct file *file;
	struct list_head attachments;
	const struct dma_buf_ops *ops;
	/* mutex to serialize list manipulation, attach/detach and vmap/unmap */
	struct mutex lock;
	unsigned vmapping_counter;
	void *vmap_ptr;
	const char *exp_name;
	struct list_head list_node;
	void *priv;
	struct reservation_object *resv;

	/* poll support */
	wait_queue_head_t poll;

	struct dma_buf_poll_cb_t {
		struct dma_fence_cb cb;
		wait_queue_head_t *poll;

		unsigned long active;
	} cb_excl, cb_shared;
};

/**
 * struct dma_buf_attachment - holds device-buffer attachment data
 * @dmabuf: buffer for this attachment.
 * @dev: device attached to the buffer.
 * @node: list of dma_buf_attachment.
 * @priv: exporter specific attachment data.
 *
 * This structure holds the attachment information between the dma_buf buffer
 * and its user device(s). The list contains one attachment struct per device
 * attached to the buffer.
 *
 * An attachment is created by calling dma_buf_attach(), and released again by
 * calling dma_buf_detach(). The DMA mapping itself needed to initiate a
 * transfer is created by dma_buf_map_attachment() and freed again by calling
 * dma_buf_unmap_attachment().
 */
struct dma_buf_attachment {
	struct dma_buf *dmabuf;
	struct device *dev;
	struct list_head node;
	void *priv;
};

/**
 * get_dma_buf - convenience wrapper for get_file.
 * @dmabuf:	[in]	pointer to dma_buf
 *
 * Increments the reference count on the dma-buf, needed in case of drivers
 * that either need to create additional references to the dmabuf on the
 * kernel side.  For example, an exporter that needs to keep a dmabuf ptr
 * so that subsequent exports don't create a new dmabuf.
 */
static inline void get_dma_buf(struct dma_buf *dmabuf)
{
	get_file(dmabuf->file);
}

struct dma_buf_attachment *dma_buf_attach(struct dma_buf *dmabuf,
							struct device *dev);
void dma_buf_detach(struct dma_buf *dmabuf,
				struct dma_buf_attachment *dmabuf_attach);

struct dma_buf *dma_buf_export_named(void *priv, const struct dma_buf_ops *ops,
			       size_t size, int flags, const char *,
			       struct reservation_object *);

#define dma_buf_export(priv, ops, size, flags, resv)	\
	dma_buf_export_named(priv, ops, size, flags, KBUILD_MODNAME, resv)

int dma_buf_fd(struct dma_buf *dmabuf, int flags);
struct dma_buf *dma_buf_get(int fd);
void dma_buf_put(struct dma_buf *dmabuf);

int dma_buf_set_drvdata(struct dma_buf *, struct device *,
			void *, void (*destroy)(void *));
void *dma_buf_get_drvdata(struct dma_buf *, struct device *);

struct sg_table *dma_buf_map_attachment(struct dma_buf_attachment *,
					enum dma_data_direction);
void dma_buf_unmap_attachment(struct dma_buf_attachment *, struct sg_table *,
				enum dma_data_direction);
int dma_buf_begin_cpu_access(struct dma_buf *dma_buf,
			     enum dma_data_direction dir);
int dma_buf_end_cpu_access(struct dma_buf *dma_buf,
			   enum dma_data_direction dir);
void *dma_buf_kmap_atomic(struct dma_buf *, unsigned long);
void dma_buf_kunmap_atomic(struct dma_buf *, unsigned long, void *);
void *dma_buf_kmap(struct dma_buf *, unsigned long);
void dma_buf_kunmap(struct dma_buf *, unsigned long, void *);

int dma_buf_mmap(struct dma_buf *, struct vm_area_struct *,
		 unsigned long);
void *dma_buf_vmap(struct dma_buf *);
void dma_buf_vunmap(struct dma_buf *, void *vaddr);
int dma_buf_debugfs_create_file(const char *name,
				int (*write)(struct seq_file *));

bool dmabuf_is_ion(struct dma_buf *dmabuf);
#endif /* __DMA_BUF_H__ */
