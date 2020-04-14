#ifndef _UART16550_H
#define _UART16550_H

#define	OPTION_COM1			1
#define OPTION_COM2			2
#define OPTION_BOTH			3

#define UART16550_COM1_SELECTED		0x01
#define UART16550_COM2_SELECTED		0x02

#define BUFFER_SIZE			PAGE_SIZE
#define MODULE_NAME			"uart16550"

/* Id of device in devices array */
#define COM1_IDX			0
#define COM2_IDX			1

/* Character device info */
#define DEFAULT_MAJOR			42
#define COM1_MINOR			0
#define COM2_MINOR			1
#define MAX_MINORS			2

/* Interrupt numbers */
#define IRQ_COM1			4
#define IRQ_COM2			3

/* Ports addresses and size */
#define COM1_REG			0x3f8
#define COM2_REG			0x2f8
#define REG_SIZE			8

/* Registers offsets */
#define RBR_OFFSET			0
#define THR_OFFSET			0
#define DLL_OFFSET			0
#define DLM_OFFSET			1
#define IER_OFFSET			1
#define IIR_OFFSET			2
#define LCR_OFFSET			3
#define MCR_OFFSET			4
#define LSR_OFFSET			5
#define MSR_OFFSET			6
#define SCR_OFFSET			7

/* Useful masks */
#define INTR_EN_MASK			0x08
#define INTR_PEND_MASK			0x01
#define INTR_ID_MASK			0x0e
#define THREI_MASK			0x02
#define RDAI_MASK			0x01

/* Interrupt IDs */
#define RDAI_ID				0x04
#define THREI_ID			0x02

#ifndef _UART16550_REGS_H


#define UART16550_BAUD_1200		96
#define UART16550_BAUD_2400		48
#define UART16550_BAUD_4800		24
#define UART16550_BAUD_9600		12
#define UART16550_BAUD_19200		6
#define UART16550_BAUD_38400		3
#define UART16550_BAUD_56000		2
#define UART16550_BAUD_115200		1

#define UART16550_LEN_5			0x00
#define UART16550_LEN_6			0x01
#define UART16550_LEN_7			0x02
#define UART16550_LEN_8			0x03

#define UART16550_STOP_1		0x00
#define UART16550_STOP_2		0x04

#define UART16550_PAR_NONE		0x00
#define UART16550_PAR_ODD		0x08
#define UART16550_PAR_EVEN		0x18
#define UART16550_PAR_STICK		0x20

#endif

#define	UART16550_IOCTL_SET_LINE	1

struct uart16550_line_info {
	unsigned char baud, len, par, stop;
};


#endif
