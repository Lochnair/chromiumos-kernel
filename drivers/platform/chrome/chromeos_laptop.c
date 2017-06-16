/*
 *  chromeos_laptop.c - Driver to instantiate Chromebook i2c/smbus devices.
 *
 *  Author : Benson Leung <bleung@chromium.org>
 *
 *  Copyright (C) 2012 Google, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <linux/dmi.h>
#include <linux/gpio.h>
#include <linux/i2c.h>
#include <linux/i2c/atmel_mxt_ts.h>
#include <linux/input.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/gpio_keys.h>
#include <uapi/linux/input.h>

#define ATMEL_TP_I2C_ADDR	0x4b
#define ATMEL_TP_I2C_BL_ADDR	0x25
#define ATMEL_TS_I2C_ADDR	0x4a
#define ATMEL_TS_I2C_BL_ADDR	0x26
#define CYAPA_TP_I2C_ADDR	0x67
#define ISL_ALS_I2C_ADDR	0x44
#define TAOS_ALS_I2C_ADDR	0x29

#define MAX_I2C_DEVICE_DEFERRALS	5

static struct i2c_client *als;
static struct i2c_client *tp;
static struct i2c_client *ts;

static const char *i2c_adapter_names[] = {
	"SMBus I801 adapter",
	"i915 gmbus vga",
	"i915 gmbus panel",
	"i2c-designware-pci",
	"i2c-designware-pci",
};

/* Keep this enum consistent with i2c_adapter_names */
enum i2c_adapter_type {
	I2C_ADAPTER_SMBUS = 0,
	I2C_ADAPTER_VGADDC,
	I2C_ADAPTER_PANEL,
	I2C_ADAPTER_DESIGNWARE_0,
	I2C_ADAPTER_DESIGNWARE_1,
};

enum i2c_peripheral_state {
	UNPROBED = 0,
	PROBED,
	TIMEDOUT,
};

struct i2c_peripheral {
	int (*add)(enum i2c_adapter_type type);
	enum i2c_adapter_type type;
	enum i2c_peripheral_state state;
	int tries;
};

#define MAX_I2C_PERIPHERALS 4

struct chromeos_laptop {
	struct i2c_peripheral i2c_peripherals[MAX_I2C_PERIPHERALS];
	bool has_keyboard_backlight;
	int (*platform_init)(void);
	int (*platform_exit)(void);
};

static struct chromeos_laptop *cros_laptop;

static struct i2c_board_info cyapa_device = {
	I2C_BOARD_INFO("cyapa", CYAPA_TP_I2C_ADDR),
	.flags		= I2C_CLIENT_WAKE,
};

static struct i2c_board_info isl_als_device = {
	I2C_BOARD_INFO("isl29018", ISL_ALS_I2C_ADDR),
};

static struct i2c_board_info tsl2583_als_device = {
	I2C_BOARD_INFO("tsl2583", TAOS_ALS_I2C_ADDR),
};

static struct i2c_board_info tsl2563_als_device = {
	I2C_BOARD_INFO("tsl2563", TAOS_ALS_I2C_ADDR),
};

static struct i2c_board_info atmel_224s_tp_device = {
	I2C_BOARD_INFO("atmel_mxt_tp", ATMEL_TP_I2C_ADDR),
	.flags		= I2C_CLIENT_WAKE,
};

static struct i2c_board_info atmel_1664s_device = {
	I2C_BOARD_INFO("atmel_mxt_ts", ATMEL_TS_I2C_ADDR),
	.flags		= I2C_CLIENT_WAKE,
};

static struct i2c_client *__add_probed_i2c_device(
		const char *name,
		int bus,
		struct i2c_board_info *info,
		const unsigned short *addrs)
{
	const struct dmi_device *dmi_dev;
	const struct dmi_dev_onboard *dev_data;
	struct i2c_adapter *adapter;
	struct i2c_client *client;

	if (bus < 0)
		return NULL;
	/*
	 * If a name is specified, look for irq platform information stashed
	 * in DMI_DEV_TYPE_DEV_ONBOARD by the Chrome OS custom system firmware.
	 */
	if (name) {
		dmi_dev = dmi_find_device(DMI_DEV_TYPE_DEV_ONBOARD, name, NULL);
		if (!dmi_dev) {
			pr_err("%s failed to dmi find device %s.\n",
			       __func__,
			       name);
			return NULL;
		}
		dev_data = (struct dmi_dev_onboard *)dmi_dev->device_data;
		if (!dev_data) {
			pr_err("%s failed to get data from dmi for %s.\n",
			       __func__, name);
			return NULL;
		}

		/* Use Peripheral IRQ if devfn is 0, otherwise use GPIO IRQ */
		if (dev_data->devfn != 0)
			info->irq = gpio_to_irq(dev_data->instance);
		else
			info->irq = dev_data->instance;
	}

	adapter = i2c_get_adapter(bus);
	if (!adapter) {
		pr_err("%s failed to get i2c adapter %d.\n", __func__, bus);
		return NULL;
	}

	/* add the i2c device */
	client = i2c_new_probed_device(adapter, info, addrs, NULL);
	if (!client)
		pr_notice("%s failed to register device %d-%02x\n",
			  __func__, bus, info->addr);
	else
		pr_debug("%s added i2c device %d-%02x\n",
			 __func__, bus, info->addr);

	i2c_put_adapter(adapter);
	return client;
}

struct i2c_lookup {
	const char *name;
	int instance;
	int n;
};

static int __find_i2c_adap(struct device *dev, void *data)
{
	struct i2c_lookup *lookup = data;
	static const char *prefix = "i2c-";
	struct i2c_adapter *adapter;

	if (strncmp(dev_name(dev), prefix, strlen(prefix)) != 0)
		return 0;
	adapter = to_i2c_adapter(dev);
	if (strncmp(adapter->name, lookup->name, strlen(lookup->name)) == 0 &&
	    lookup->n++ == lookup->instance)
		return 1;
	return 0;
}

static int find_i2c_adapter_num(enum i2c_adapter_type type)
{
	struct device *dev = NULL;
	struct i2c_adapter *adapter;
	struct i2c_lookup lookup;

	memset(&lookup, 0, sizeof(lookup));
	lookup.name = i2c_adapter_names[type];
	lookup.instance = (type == I2C_ADAPTER_DESIGNWARE_1) ? 1 : 0;

	/* find the adapter by name */
	dev = bus_find_device(&i2c_bus_type, NULL, &lookup, __find_i2c_adap);
	if (!dev) {
		/* Adapters may appear later. Deferred probing will retry */
		pr_notice("%s: i2c adapter %s not found on system.\n", __func__,
			  lookup.name);
		return -ENODEV;
	}
	adapter = to_i2c_adapter(dev);
	return adapter->nr;
}

/*
 * Takes a list of addresses in addrs as such :
 * { addr1, ... , addrn, I2C_CLIENT_END };
 * add_probed_i2c_device will use i2c_new_probed_device
 * and probe for devices at all of the addresses listed.
 * Returns NULL if no devices found.
 * See Documentation/i2c/instantiating-devices for more information.
 */
static struct i2c_client *add_probed_i2c_device(
		const char *name,
		enum i2c_adapter_type type,
		struct i2c_board_info *info,
		const unsigned short *addrs)
{
	return __add_probed_i2c_device(name,
				       find_i2c_adapter_num(type),
				       info,
				       addrs);
}

/*
 * Probes for a device at a single address, the one provided by
 * info->addr.
 * Returns NULL if no device found.
 */
static struct i2c_client *add_i2c_device(const char *name,
						enum i2c_adapter_type type,
						struct i2c_board_info *info)
{
	const unsigned short addr_list[] = { info->addr, I2C_CLIENT_END };

	return __add_probed_i2c_device(name,
				       find_i2c_adapter_num(type),
				       info,
				       addr_list);
}

static int setup_cyapa_tp(enum i2c_adapter_type type)
{
	if (tp)
		return 0;

	/* add cyapa touchpad */
	tp = add_i2c_device("trackpad", type, &cyapa_device);
	return (!tp) ? -EAGAIN : 0;
}

static int setup_atmel_224s_tp(enum i2c_adapter_type type)
{
	const unsigned short addr_list[] = { ATMEL_TP_I2C_BL_ADDR,
					     ATMEL_TP_I2C_ADDR,
					     I2C_CLIENT_END };
	if (tp)
		return 0;

	/* add atmel mxt touchpad */
	tp = add_probed_i2c_device("trackpad", type,
				   &atmel_224s_tp_device, addr_list);
	return (!tp) ? -EAGAIN : 0;
}

static int setup_atmel_1664s_ts(enum i2c_adapter_type type)
{
	const unsigned short addr_list[] = { ATMEL_TS_I2C_BL_ADDR,
					     ATMEL_TS_I2C_ADDR,
					     I2C_CLIENT_END };
	if (ts)
		return 0;

	/* add atmel mxt touch device */
	ts = add_probed_i2c_device("touchscreen", type,
				   &atmel_1664s_device, addr_list);
	return (!ts) ? -EAGAIN : 0;
}

static int setup_isl29018_als(enum i2c_adapter_type type)
{
	if (als)
		return 0;

	/* add isl29018 light sensor */
	als = add_i2c_device("lightsensor", type, &isl_als_device);
	return (!als) ? -EAGAIN : 0;
}

static int setup_tsl2583_als(enum i2c_adapter_type type)
{
	if (als)
		return 0;

	/* add tsl2583 light sensor */
	als = add_i2c_device(NULL, type, &tsl2583_als_device);
	return (!als) ? -EAGAIN : 0;
}

static int setup_tsl2563_als(enum i2c_adapter_type type)
{
	if (als)
		return 0;

	/* add tsl2563 light sensor */
	als = add_i2c_device(NULL, type, &tsl2563_als_device);
	return (!als) ? -EAGAIN : 0;
}

static struct platform_device *kb_backlight_device;

static void setup_keyboard_backlight(void)
{
	if (kb_backlight_device)
		return;

	kb_backlight_device =
		platform_device_register_simple("chromeos-keyboard-leds",
						-1, NULL, 0);
	if (IS_ERR(kb_backlight_device)) {
		pr_warn("Error registering Chrome OS keyboard LEDs.\n");
		kb_backlight_device = NULL;
	}
}

static int __init chromeos_laptop_dmi_matched(const struct dmi_system_id *id)
{
	cros_laptop = (void *)id->driver_data;
	pr_debug("DMI Matched %s.\n", id->ident);

	/* Indicate to dmi_scan that processing is done. */
	return 1;
}

static int gpiochip_match_name(struct gpio_chip *chip, void *data)
{
	const char *name = data;

	return !strcmp(chip->label, name);
}

static struct gpio_chip *find_gpiochip_by_name(const char *name)
{
	return gpiochip_find((void *)name, gpiochip_match_name);
}

static struct gpio_keys_button caroline_buttons[] = {
	{
		.code = SW_PEN_INSERTED,
		.active_low = 1,
		.desc = "Pen Eject",
		.type = EV_SW,
	},
};

static struct gpio_keys_platform_data caroline_gpio_keys_data = {
	.buttons = caroline_buttons,
	.nbuttons = 1,
};

static struct platform_device caroline_gpio_keys_dev = {
	.name = "gpio-keys",
	.dev = {
		.platform_data = &caroline_gpio_keys_data,
	},
};

#define CAROLINE_GPIO_B19   (43)

static bool caroline_gpio_keys_dev_registered;

static int caroline_platform_init(void)
{
	int ret;
	struct gpio_chip *gc;

	if (caroline_gpio_keys_dev_registered)
		return 0;

	gc = find_gpiochip_by_name("INT344B:00");
	if (!gc)
		return -EPROBE_DEFER;

	if (gc->ngpio <= CAROLINE_GPIO_B19) {
		pr_err("%s: INT344B:00 has no pin for gpio-keys (%d)?\n",
		       __func__, CAROLINE_GPIO_B19);
		return -ENODEV;
	}
	caroline_buttons[0].gpio = gc->base + CAROLINE_GPIO_B19;

	ret = platform_device_register(&caroline_gpio_keys_dev);
	if (ret)
		return ret;

	caroline_gpio_keys_dev_registered = true;
	return 0;
}

static int caroline_platform_exit(void)
{
	if (caroline_gpio_keys_dev_registered)
		platform_device_unregister(&caroline_gpio_keys_dev);

	caroline_gpio_keys_dev_registered = false;
	return 0;
}

static int chromeos_laptop_probe(struct platform_device *pdev)
{
	int i;
	int ret = 0;

	if (cros_laptop->platform_init)
		ret = cros_laptop->platform_init();

	for (i = 0; i < MAX_I2C_PERIPHERALS; i++) {
		struct i2c_peripheral *i2c_dev;

		i2c_dev = &cros_laptop->i2c_peripherals[i];

		/* No more peripherals. */
		if (i2c_dev->add == NULL)
			break;

		if (i2c_dev->state == TIMEDOUT || i2c_dev->state == PROBED)
			continue;

		/*
		 * Check that the i2c adapter is present.
		 * -EPROBE_DEFER if missing as the adapter may appear much
		 * later.
		 */
		if (find_i2c_adapter_num(i2c_dev->type) == -ENODEV) {
			ret = -EPROBE_DEFER;
			continue;
		}

		/* Add the device. */
		if (i2c_dev->add(i2c_dev->type) == -EAGAIN) {
			/*
			 * Set -EPROBE_DEFER a limited num of times
			 * if device is not successfully added.
			 */
			if (++i2c_dev->tries < MAX_I2C_DEVICE_DEFERRALS) {
				ret = -EPROBE_DEFER;
			} else {
				/* Ran out of tries. */
				pr_notice("%s: Ran out of tries for device.\n",
					  __func__);
				i2c_dev->state = TIMEDOUT;
			}
		} else {
			i2c_dev->state = PROBED;
		}
	}

	/* Add keyboard backlight device if present. */
	if (cros_laptop->has_keyboard_backlight)
		setup_keyboard_backlight();

	return ret;
}

static int chromeos_laptop_remove(struct platform_device *pdev)
{
	if (cros_laptop->platform_exit)
		return cros_laptop->platform_exit();

	return 0;
}

static struct chromeos_laptop samsung_series_5_550 = {
	.i2c_peripherals = {
		/* Touchpad. */
		{ .add = setup_cyapa_tp, I2C_ADAPTER_SMBUS },
		/* Light Sensor. */
		{ .add = setup_isl29018_als, I2C_ADAPTER_SMBUS },
	},
};

static struct chromeos_laptop samsung_series_5 = {
	.i2c_peripherals = {
		/* Light Sensor. */
		{ .add = setup_tsl2583_als, I2C_ADAPTER_SMBUS },
	},
};

static struct chromeos_laptop chromebook_pixel = {
	.i2c_peripherals = {
		/* Touch Screen. */
		{ .add = setup_atmel_1664s_ts, I2C_ADAPTER_PANEL },
		/* Touchpad. */
		{ .add = setup_atmel_224s_tp, I2C_ADAPTER_VGADDC },
		/* Light Sensor. */
		{ .add = setup_isl29018_als, I2C_ADAPTER_PANEL },
	},
	.has_keyboard_backlight = true,
};

static struct chromeos_laptop hp_chromebook_14 = {
	.i2c_peripherals = {
		/* Touchpad. */
		{ .add = setup_cyapa_tp, I2C_ADAPTER_DESIGNWARE_0 },
	},
};

static struct chromeos_laptop dell_chromebook_11 = {
	.i2c_peripherals = {
		/* Touchpad. */
		{ .add = setup_cyapa_tp, I2C_ADAPTER_DESIGNWARE_0 },
	},
};

static struct chromeos_laptop toshiba_cb35 = {
	.i2c_peripherals = {
		/* Touchpad. */
		{ .add = setup_cyapa_tp, I2C_ADAPTER_DESIGNWARE_0 },
	},
};

static struct chromeos_laptop wolf = {
	.i2c_peripherals = {
		/* Touchpad. */
		{ .add = setup_cyapa_tp, I2C_ADAPTER_DESIGNWARE_0 },
	},
};

static struct chromeos_laptop leon = {
	.i2c_peripherals = {
		/* Touchpad. */
		{ .add = setup_cyapa_tp, I2C_ADAPTER_DESIGNWARE_0 },
	},
};

static struct chromeos_laptop acer_c7_chromebook = {
	.i2c_peripherals = {
		/* Touchpad. */
		{ .add = setup_cyapa_tp, I2C_ADAPTER_SMBUS },
	},
};

static struct chromeos_laptop acer_ac700 = {
	.i2c_peripherals = {
		/* Light Sensor. */
		{ .add = setup_tsl2563_als, I2C_ADAPTER_SMBUS },
	},
};

static struct chromeos_laptop acer_c720 = {
	.i2c_peripherals = {
		/* Touchscreen. */
		{ .add = setup_atmel_1664s_ts, I2C_ADAPTER_DESIGNWARE_1 },
		/* Touchpad. */
		{ .add = setup_cyapa_tp, I2C_ADAPTER_DESIGNWARE_0 },
		/* Light Sensor. */
		{ .add = setup_isl29018_als, I2C_ADAPTER_DESIGNWARE_1 },
	},
};

static struct chromeos_laptop hp_pavilion_14_chromebook = {
	.i2c_peripherals = {
		/* Touchpad. */
		{ .add = setup_cyapa_tp, I2C_ADAPTER_SMBUS },
	},
};

static struct chromeos_laptop cr48 = {
	.i2c_peripherals = {
		/* Light Sensor. */
		{ .add = setup_tsl2563_als, I2C_ADAPTER_SMBUS },
	},
};

static struct chromeos_laptop bolt = {
	.i2c_peripherals = {
		/* Touchscreen. */
		{ .add = setup_atmel_1664s_ts, I2C_ADAPTER_DESIGNWARE_1 },
		/* Touchpad. */
		{ .add = setup_atmel_224s_tp, I2C_ADAPTER_DESIGNWARE_0 },
		/* Light Sensor. */
		{ .add = setup_isl29018_als, I2C_ADAPTER_DESIGNWARE_1 },
	},
	.has_keyboard_backlight = true,
};

static struct chromeos_laptop caroline = {
	.platform_init = caroline_platform_init,
	.platform_exit = caroline_platform_exit,
};

#define _CBDD(board_) \
	.callback = chromeos_laptop_dmi_matched, \
	.driver_data = (void *)&board_

static struct dmi_system_id chromeos_laptop_dmi_table[] __initdata = {
	{
		.ident = "Samsung Series 5 550",
		.matches = {
			DMI_MATCH(DMI_SYS_VENDOR, "SAMSUNG"),
			DMI_MATCH(DMI_PRODUCT_NAME, "Lumpy"),
		},
		_CBDD(samsung_series_5_550),
	},
	{
		.ident = "Samsung Series 5",
		.matches = {
			DMI_MATCH(DMI_PRODUCT_NAME, "Alex"),
		},
		_CBDD(samsung_series_5),
	},
	{
		.ident = "Chromebook Pixel",
		.matches = {
			DMI_MATCH(DMI_SYS_VENDOR, "GOOGLE"),
			DMI_MATCH(DMI_PRODUCT_NAME, "Link"),
		},
		_CBDD(chromebook_pixel),
	},
	{
		.ident = "Wolf",
		.matches = {
			DMI_MATCH(DMI_BIOS_VENDOR, "coreboot"),
			DMI_MATCH(DMI_PRODUCT_NAME, "Wolf"),
		},
		_CBDD(dell_chromebook_11),
	},
	{
		.ident = "HP Chromebook 14",
		.matches = {
			DMI_MATCH(DMI_BIOS_VENDOR, "coreboot"),
			DMI_MATCH(DMI_PRODUCT_NAME, "Falco"),
		},
		_CBDD(hp_chromebook_14),
	},
	{
		.ident = "Toshiba CB35",
		.matches = {
			DMI_MATCH(DMI_BIOS_VENDOR, "coreboot"),
			DMI_MATCH(DMI_PRODUCT_NAME, "Leon"),
		},
		_CBDD(toshiba_cb35),
	},
	{
		.ident = "Wolf",
		.matches = {
			DMI_MATCH(DMI_BIOS_VENDOR, "coreboot"),
			DMI_MATCH(DMI_PRODUCT_NAME, "Wolf"),
		},
		_CBDD(wolf),
	},
	{
		.ident = "Leon",
		.matches = {
			DMI_MATCH(DMI_BIOS_VENDOR, "coreboot"),
			DMI_MATCH(DMI_PRODUCT_NAME, "Leon"),
		},
		_CBDD(leon),
	},
	{
		.ident = "Acer C7 Chromebook",
		.matches = {
			DMI_MATCH(DMI_PRODUCT_NAME, "Parrot"),
		},
		_CBDD(acer_c7_chromebook),
	},
	{
		.ident = "Acer AC700",
		.matches = {
			DMI_MATCH(DMI_PRODUCT_NAME, "ZGB"),
		},
		_CBDD(acer_ac700),
	},
	{
		.ident = "Acer C720",
		.matches = {
			DMI_MATCH(DMI_PRODUCT_NAME, "Peppy"),
		},
		_CBDD(acer_c720),
	},
	{
		.ident = "HP Pavilion 14 Chromebook",
		.matches = {
			DMI_MATCH(DMI_PRODUCT_NAME, "Butterfly"),
		},
		_CBDD(hp_pavilion_14_chromebook),
	},
	{
		.ident = "Cr-48",
		.matches = {
			DMI_MATCH(DMI_PRODUCT_NAME, "Mario"),
		},
		_CBDD(cr48),
	},
	{
		.ident = "Bolt",
		.matches = {
			DMI_MATCH(DMI_BIOS_VENDOR, "coreboot"),
			DMI_MATCH(DMI_PRODUCT_NAME, "Bolt"),
		},
		_CBDD(bolt),
	},
	{
		.ident = "Caroline",
		.matches = {
			DMI_MATCH(DMI_PRODUCT_NAME, "Caroline"),
		},
		_CBDD(caroline),
	},
	{ }
};
MODULE_DEVICE_TABLE(dmi, chromeos_laptop_dmi_table);

static struct platform_device *cros_platform_device;

static struct platform_driver cros_platform_driver = {
	.driver = {
		.name = "chromeos_laptop",
		.owner = THIS_MODULE,
	},
	.probe = chromeos_laptop_probe,
	.remove = chromeos_laptop_remove,
};

static int __init chromeos_laptop_init(void)
{
	int ret;

	if (!dmi_check_system(chromeos_laptop_dmi_table)) {
		pr_debug("%s unsupported system.\n", __func__);
		return -ENODEV;
	}

	ret = platform_driver_register(&cros_platform_driver);
	if (ret)
		return ret;

	cros_platform_device = platform_device_alloc("chromeos_laptop", -1);
	if (!cros_platform_device) {
		ret = -ENOMEM;
		goto fail_platform_device1;
	}

	ret = platform_device_add(cros_platform_device);
	if (ret)
		goto fail_platform_device2;

	return 0;

fail_platform_device2:
	platform_device_put(cros_platform_device);
fail_platform_device1:
	platform_driver_unregister(&cros_platform_driver);
	return ret;
}

static void __exit chromeos_laptop_exit(void)
{
	if (als)
		i2c_unregister_device(als);
	if (tp)
		i2c_unregister_device(tp);
	if (ts)
		i2c_unregister_device(ts);
	if (kb_backlight_device)
		platform_device_unregister(kb_backlight_device);

	platform_device_unregister(cros_platform_device);
	platform_driver_unregister(&cros_platform_driver);
}

module_init(chromeos_laptop_init);
module_exit(chromeos_laptop_exit);

MODULE_DESCRIPTION("Chrome OS Laptop driver");
MODULE_AUTHOR("Benson Leung <bleung@chromium.org>");
MODULE_LICENSE("GPL");
