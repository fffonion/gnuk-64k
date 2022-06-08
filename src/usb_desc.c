/*
 * usb_desc.c - USB Descriptor
 */

#include <stdint.h>
#include <string.h>

#include "config.h"

#include "sys.h"
#include "usb_lld.h"
#include "usb_conf.h"
#include "usb-cdc.h"


#define USB_CCID_INTERFACE_CLASS 0x0B
#define USB_CCID_INTERFACE_SUBCLASS 0x00
#define USB_CCID_INTERFACE_BULK_PROTOCOL 0x00
#define USB_CCID_DATA_SIZE 64

/* USB Standard Device Descriptor */
#if !defined(GNU_LINUX_EMULATION)
static const
#endif
uint8_t device_desc[] = {
  18,   /* bLength */
  DEVICE_DESCRIPTOR,     /* bDescriptorType */
  0x00, 0x02,            /* bcdUSB = 2.0 */
  0x00,   /* bDeviceClass: 0 means deferred to interface */
  0x00,   /* bDeviceSubClass */
  0x00,   /* bDeviceProtocol */
  0x40,   /* bMaxPacketSize0 */
  0x00, 0x00,			/* idVendor  (will be replaced)     */
  0x00, 0x00,			/* idProduct (will be replaced)     */
  0x00, 0x00,			/* bcdDevice (will be replaced)     */
  1, /* Index of string descriptor describing manufacturer */
  2, /* Index of string descriptor describing product */
  3, /* Index of string descriptor describing the device's serial number */
  0x01    /* bNumConfigurations */
};

#define CCID_TOTAL_LENGTH (9+9+54+7+7+7)

#define HID_TOTAL_LENGTH   0

#ifdef ENABLE_VIRTUAL_COM_PORT
#define VCOM_TOTAL_LENGTH (9+5+5+4+5+7+9+7+7)
#else
#define VCOM_TOTAL_LENGTH   0
#endif

#define W_TOTAL_LENGTH (CCID_TOTAL_LENGTH + VCOM_TOTAL_LENGTH)


/* Configuation Descriptor */
static const uint8_t config_desc[] = {
  9,			   /* bLength: Configuation Descriptor size */
  CONFIG_DESCRIPTOR,	   /* bDescriptorType: Configuration */
  W_TOTAL_LENGTH, 0x00,	   /* wTotalLength:no of returned bytes */
  NUM_INTERFACES,	   /* bNumInterfaces: */
  0x01,   /* bConfigurationValue: Configuration value */
  0x00,   /* iConfiguration: Index of string descriptor describing the configuration */
  USB_INITIAL_FEATURE,  /* bmAttributes*/
  50,	  /* MaxPower 100 mA */

  /* Interface Descriptor */
  9,			         /* bLength: Interface Descriptor size */
  INTERFACE_DESCRIPTOR,		 /* bDescriptorType: Interface */
  CCID_INTERFACE,	         /* bInterfaceNumber: Index of this interface */
  0,			         /* Alternate setting for this interface */
  3,			         /* bNumEndpoints: Bulk-IN, Bulk-OUT, Intr-IN */
  USB_CCID_INTERFACE_CLASS,
  USB_CCID_INTERFACE_SUBCLASS,
  USB_CCID_INTERFACE_BULK_PROTOCOL,
  0,				 /* string index for interface */

  /* ICC Descriptor */
  54,			  /* bLength: */
  0x21,			  /* bDescriptorType: USBDESCR_ICC */
  0x10, 0x01,		  /* bcdCCID: revision 1.1 (of CCID) */
  0,			  /* bMaxSlotIndex: */
  1,			  /* bVoltageSupport: 5V-only */
  0x02, 0, 0, 0,	  /* dwProtocols: T=1 */
  0xa0, 0x0f, 0, 0,	  /* dwDefaultClock: 4000 */
  0xa0, 0x0f, 0, 0,	  /* dwMaximumClock: 4000 */
  0,			  /* bNumClockSupported: 0x00 */
  0x80, 0x25, 0, 0,	  /* dwDataRate: 9600 */
  0x80, 0x25, 0, 0,	  /* dwMaxDataRate: 9600 */
  0,			  /* bNumDataRateSupported: 0x00 */
  0xfe, 0, 0, 0,	  /* dwMaxIFSD: 254 */
  0, 0, 0, 0,		  /* dwSynchProtocols: 0 */
  0, 0, 0, 0,		  /* dwMechanical: 0 */
  0x7a, 0x04, 0x02, 0x00, /* dwFeatures:
			   *  Short and extended APDU level: 0x40000 ----
			   *  Short APDU level             : 0x20000  *
			   *  (ICCD?)                      : 0x00800 ----
			   *  Automatic IFSD               : 0x00400   *
			   *  NAD value other than 0x00    : 0x00200
			   *  Can set ICC in clock stop    : 0x00100
			   *  Automatic PPS CUR            : 0x00080
			   *  Automatic PPS PROP           : 0x00040 *
			   *  Auto baud rate change	   : 0x00020   *
			   *  Auto clock change		   : 0x00010   *
			   *  Auto voltage selection	   : 0x00008   *
			   *  Auto activaction of ICC	   : 0x00004
			   *  Automatic conf. based on ATR : 0x00002  *
			   */
  0x0f, 0x01, 0, 0,	  /* dwMaxCCIDMessageLength: 271 */
  0xff,			  /* bClassGetResponse: 0xff */
  0x00,			  /* bClassEnvelope: 0 */
  0, 0,			  /* wLCDLayout: 0 */
  0,			  /* bPinSupport: No PIN pad */
  1,			  /* bMaxCCIDBusySlots: 1 */
  /*Endpoint IN1 Descriptor*/
  7,			       /* bLength: Endpoint Descriptor size */
  ENDPOINT_DESCRIPTOR,	       /* bDescriptorType: Endpoint */
  0x81,				/* bEndpointAddress: (IN1) */
  0x02,				/* bmAttributes: Bulk */
  USB_CCID_DATA_SIZE, 0x00,      /* wMaxPacketSize: */
  0x00,				/* bInterval */
  /*Endpoint OUT1 Descriptor*/
  7,			       /* bLength: Endpoint Descriptor size */
  ENDPOINT_DESCRIPTOR,	       /* bDescriptorType: Endpoint */
  0x01,				/* bEndpointAddress: (OUT1) */
  0x02,				/* bmAttributes: Bulk */
  USB_CCID_DATA_SIZE, 0x00,	/* wMaxPacketSize: */
  0x00,				/* bInterval */
  /*Endpoint IN2 Descriptor*/
  7,			       /* bLength: Endpoint Descriptor size */
  ENDPOINT_DESCRIPTOR,	       /* bDescriptorType: Endpoint */
  0x82,				/* bEndpointAddress: (IN2) */
  0x03,				/* bmAttributes: Interrupt */
  0x04, 0x00,			/* wMaxPacketSize: 4 */
  0xFF,				/* bInterval (255ms) */

#ifdef ENABLE_VIRTUAL_COM_PORT
  /* Interface Descriptor */
  9,			      /* bLength: Interface Descriptor size */
  INTERFACE_DESCRIPTOR,	      /* bDescriptorType: Interface */
  VCOM_INTERFACE_0,	 /* bInterfaceNumber: Index of Interface */
  0x00,		  /* bAlternateSetting: Alternate setting */
  0x01,		  /* bNumEndpoints: One endpoints used */
  0x02,		  /* bInterfaceClass: Communication Interface Class */
  0x02,		  /* bInterfaceSubClass: Abstract Control Model */
  0x01,		  /* bInterfaceProtocol: Common AT commands */
  0x00,		  /* iInterface: */
  /*Header Functional Descriptor*/
  5,			    /* bLength: Endpoint Descriptor size */
  0x24,			    /* bDescriptorType: CS_INTERFACE */
  0x00,			    /* bDescriptorSubtype: Header Func Desc */
  0x10, 0x01,		    /* bcdCDC: spec release number */
  /*Call Managment Functional Descriptor*/
  5,	    /* bFunctionLength */
  0x24,	    /* bDescriptorType: CS_INTERFACE */
  0x01,	    /* bDescriptorSubtype: Call Management Func Desc */
  0x03,	    /* bmCapabilities: D0+D1 */
  VCOM_INTERFACE_1,	    /* bDataInterface */
  /*ACM Functional Descriptor*/
  4,	    /* bFunctionLength */
  0x24,	    /* bDescriptorType: CS_INTERFACE */
  0x02,	    /* bDescriptorSubtype: Abstract Control Management desc */
  0x02,	    /* bmCapabilities */
  /*Union Functional Descriptor*/
  5,		 /* bFunctionLength */
  0x24,		 /* bDescriptorType: CS_INTERFACE */
  0x06,		 /* bDescriptorSubtype: Union func desc */
  VCOM_INTERFACE_0,	 /* bMasterInterface: Communication class interface */
  VCOM_INTERFACE_1,	 /* bSlaveInterface0: Data Class Interface */
  /*Endpoint 4 Descriptor*/
  7,			       /* bLength: Endpoint Descriptor size */
  ENDPOINT_DESCRIPTOR,	       /* bDescriptorType: Endpoint */
  0x84,				   /* bEndpointAddress: (IN4) */
  0x03,				   /* bmAttributes: Interrupt */
  VIRTUAL_COM_PORT_INT_SIZE, 0x00, /* wMaxPacketSize: */
  0xFF,				   /* bInterval: */

  /*Data class interface descriptor*/
  9,			       /* bLength: Endpoint Descriptor size */
  INTERFACE_DESCRIPTOR,	       /* bDescriptorType: */
  VCOM_INTERFACE_1,	 /* bInterfaceNumber: Index of Interface */
  0x00,			   /* bAlternateSetting: Alternate setting */
  0x02,			   /* bNumEndpoints: Two endpoints used */
  0x0A,			   /* bInterfaceClass: CDC */
  0x00,			   /* bInterfaceSubClass: */
  0x00,			   /* bInterfaceProtocol: */
  0x00,			   /* iInterface: */
  /*Endpoint 5 Descriptor*/
  7,			       /* bLength: Endpoint Descriptor size */
  ENDPOINT_DESCRIPTOR,	       /* bDescriptorType: Endpoint */
  0x05,				    /* bEndpointAddress: (OUT5) */
  0x02,				    /* bmAttributes: Bulk */
  VIRTUAL_COM_PORT_DATA_SIZE, 0x00, /* wMaxPacketSize: */
  0x00,			     /* bInterval: ignore for Bulk transfer */
  /*Endpoint 3 Descriptor*/
  7,			       /* bLength: Endpoint Descriptor size */
  ENDPOINT_DESCRIPTOR,	       /* bDescriptorType: Endpoint */
  0x83,				    /* bEndpointAddress: (IN3) */
  0x02,				    /* bmAttributes: Bulk */
  VIRTUAL_COM_PORT_DATA_SIZE, 0x00, /* wMaxPacketSize: */
  0x00,				    /* bInterval */
#endif
};


/* USB String Descriptors */
static const uint8_t gnuk_string_lang_id[] = {
  4,				/* bLength */
  STRING_DESCRIPTOR,
  0x09, 0x04			/* LangID = 0x0409: US-English */
};

#define USB_STRINGS_FOR_GNUK 1
#include "usb-strings.c.inc"

struct desc
{
  const uint8_t *desc;
  uint16_t size;
};

static const struct desc string_descriptors[] = {
  {gnuk_string_lang_id, sizeof (gnuk_string_lang_id)},
  {gnuk_string_vendor, sizeof (gnuk_string_vendor)},
  {gnuk_string_product, sizeof (gnuk_string_product)},
  {gnuk_string_serial, sizeof (gnuk_string_serial)},
  {gnuk_revision_detail, sizeof (gnuk_revision_detail)},
  {gnuk_config_options, sizeof (gnuk_config_options)},
  {sys_version, sizeof (sys_version)},
};
#define NUM_STRING_DESC (sizeof (string_descriptors) / sizeof (struct desc))

#define USB_DT_HID			0x21
#define USB_DT_REPORT			0x22

int
usb_get_descriptor (struct usb_dev *dev)
{
  struct device_req *arg = &dev->dev_req;
  uint8_t rcp = arg->type & RECIPIENT;
  uint8_t desc_type = (arg->value >> 8);
  uint8_t desc_index = (arg->value & 0xff);

  if (rcp == DEVICE_RECIPIENT)
    {
      if (desc_type == DEVICE_DESCRIPTOR)
	return usb_lld_ctrl_send (dev, device_desc, sizeof (device_desc));
      else if (desc_type == CONFIG_DESCRIPTOR)
	return usb_lld_ctrl_send (dev, config_desc, sizeof (config_desc));
      else if (desc_type == STRING_DESCRIPTOR)
	{
	  if (desc_index < NUM_STRING_DESC)
	    return usb_lld_ctrl_send (dev, string_descriptors[desc_index].desc,
				      string_descriptors[desc_index].size);
#ifdef USE_SYS3
	  else if (desc_index == NUM_STRING_DESC)
	    {
	      uint8_t usbbuf[64];
	      int i;
	      size_t len;

	      for (i = 0; i < (int)sizeof (usbbuf)/2 - 2; i++)
		{
		  if (sys_board_name[i] == 0)
		    break;

		  usbbuf[i*2+2] = sys_board_name[i];
		  usbbuf[i*2+3] = 0;
		}
	      usbbuf[0] = len = i*2 + 2;
	      usbbuf[1] = STRING_DESCRIPTOR;
	      return usb_lld_ctrl_send (dev, usbbuf, len);
	    }
#endif
	}
    }

  return -1;
}
