/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2022 Intel Corporation */

#ifndef _UAPI_LINUX_I3C_MCTP_H
#define _UAPI_LINUX_I3C_MCTP_H

#include <linux/ioctl.h>
#include <linux/types.h>

/*
 * maximum possible number of struct eid_info elements stored in list
 */
#define I3C_MCTP_EID_INFO_MAX 256

/*
 * MCTP operations
 * @I3C_MCTP_SET_EID_INFO: write or overwrite already existing list of
 * CPU EID and Domain ID mappings
 * @I3C_MCTP_SET_OWN_EID: write/overwrite own EID information
 * @I3C_MCTP_IOCTL_REGISTER_DEFAULT_CLIENT: register the client to
 * process MCTP packets over I3C
 */

struct i3c_mctp_eid_info {
	__u8 eid;
	__u8 dyn_addr;
	__u8 domain_id;
};

struct i3c_mctp_set_eid_info {
	__u64 ptr;
	__u16 count;
};

struct i3c_mctp_set_own_eid {
	__u8 eid;
};

#define I3C_MCTP_IOCTL_BASE    0x69

#define I3C_MCTP_IOCTL_SET_EID_INFO \
	_IOW(I3C_MCTP_IOCTL_BASE, 0x41, struct i3c_mctp_set_eid_info)
#define I3C_MCTP_IOCTL_SET_OWN_EID \
	_IOW(I3C_MCTP_IOCTL_BASE, 0x42, struct i3c_mctp_set_own_eid)
#define I3C_MCTP_IOCTL_REGISTER_DEFAULT_CLIENT \
	_IO(I3C_MCTP_IOCTL_BASE, 0x43)

#endif /* _UAPI_LINUX_I3C_MCTP_H */
